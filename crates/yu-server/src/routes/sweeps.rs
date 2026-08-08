//! Native GET /api/sweeps/history; Python source: routes/sweep_routes.py and routes/sweep_route_helpers.py.

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};

use crate::state::SharedState;

#[derive(Default)]
struct SweepHistoryFilters {
    where_sql: Vec<String>,
    params: Vec<SqlParam>,
}

#[derive(Clone, Debug, PartialEq)]
enum SqlParam {
    I64(i64),
    F64(f64),
    String(String),
}

fn clamp_history_limit(limit: i64) -> i64 {
    limit.clamp(1, 500)
}

fn parse_history_limit(raw: Option<&String>) -> i64 {
    raw.and_then(|value| value.parse::<i64>().ok())
        .map(clamp_history_limit)
        .unwrap_or(50)
}

fn match_keys(raw: Option<&String>) -> Vec<String> {
    raw.map(|value| {
        value
            .split(',')
            .filter(|part| !part.trim().is_empty())
            .map(ToString::to_string)
            .collect()
    })
    .unwrap_or_default()
}

fn append_equal_filter(filters: &mut SweepHistoryFilters, column: &str, value: Option<Value>) {
    match value {
        Some(Value::String(value)) if !value.is_empty() => {
            filters.where_sql.push(format!("{column} = ?"));
            filters.params.push(SqlParam::String(value));
        }
        Some(Value::Number(value)) => {
            filters.where_sql.push(format!("{column} = ?"));
            if let Some(i) = value.as_i64() {
                filters.params.push(SqlParam::I64(i));
            } else if let Some(f) = value.as_f64() {
                filters.params.push(SqlParam::F64(f));
            }
        }
        _ => {}
    }
}

fn append_tolerant_filter(
    filters: &mut SweepHistoryFilters,
    column: &str,
    value: Option<f64>,
    tol: &str,
) {
    let Some(value) = value else {
        return;
    };
    let pct = if tol == "exact" {
        0.0
    } else {
        tol.parse::<f64>().unwrap_or(0.0)
    };
    if pct <= 0.0 {
        filters.where_sql.push(format!("{column} = ?"));
        filters.params.push(SqlParam::F64(value));
        return;
    }
    let eps = value.abs() * (pct / 100.0);
    filters.where_sql.push(format!("{column} BETWEEN ? AND ?"));
    filters.params.push(SqlParam::F64(value - eps));
    filters.params.push(SqlParam::F64(value + eps));
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Default)]
struct SweepReference {
    bridge: Option<String>,
    checkpoint: Option<String>,
    vae: Option<String>,
    sampler: Option<String>,
    prompt_template: Option<String>,
    negative_template: Option<String>,
    width: Option<i64>,
    height: Option<i64>,
    base_seed: Option<i64>,
    steps: Option<i64>,
    cfg: Option<f64>,
}

fn append_reference_filters(
    filters: &mut SweepHistoryFilters,
    reference: &SweepReference,
    ref_axes: &[String],
    keys: &[String],
    tol_steps: &str,
    tol_cfg: &str,
) {
    for key in keys {
        match key.as_str() {
            "bridge" => append_equal_filter(
                filters,
                "s.bridge",
                reference.bridge.clone().map(Value::String),
            ),
            "checkpoint" => append_equal_filter(
                filters,
                "s.checkpoint",
                reference.checkpoint.clone().map(Value::String),
            ),
            "vae" => {
                append_equal_filter(filters, "s.vae", reference.vae.clone().map(Value::String))
            }
            "sampler" => append_equal_filter(
                filters,
                "s.sampler",
                reference.sampler.clone().map(Value::String),
            ),
            "positive" => append_equal_filter(
                filters,
                "s.prompt_template",
                reference.prompt_template.clone().map(Value::String),
            ),
            "negative" => append_equal_filter(
                filters,
                "s.negative_template",
                reference.negative_template.clone().map(Value::String),
            ),
            "resolution" => {
                if let (Some(width), Some(height)) = (reference.width, reference.height) {
                    if width != 0 && height != 0 {
                        filters
                            .where_sql
                            .push("s.width = ? AND s.height = ?".to_string());
                        filters.params.push(SqlParam::I64(width));
                        filters.params.push(SqlParam::I64(height));
                    }
                }
            }
            "baseSeed" => append_equal_filter(
                filters,
                "s.base_seed",
                reference.base_seed.map(|v| json!(v)),
            ),
            "steps" => append_tolerant_filter(
                filters,
                "s.steps",
                reference.steps.map(|v| v as f64),
                tol_steps,
            ),
            "cfg" => append_tolerant_filter(filters, "s.cfg", reference.cfg, tol_cfg),
            "axisX" | "axisY" | "axisZ" => {
                let pos = match key.as_str() {
                    "axisX" => 0,
                    "axisY" => 1,
                    _ => 2,
                };
                if let Some(param) = ref_axes.get(pos) {
                    filters.where_sql.push(
                        "EXISTS (SELECT 1 FROM sweep_axes a WHERE a.sweep_id = s.id AND a.axis_index = ? AND a.param = ?)".to_string(),
                    );
                    filters.params.push(SqlParam::I64(pos as i64));
                    filters.params.push(SqlParam::String(param.clone()));
                }
            }
            _ => {}
        }
    }
}

fn append_constraint_filters(
    filters: &mut SweepHistoryFilters,
    completed_only: bool,
    saved_only: bool,
    axis_count: &str,
    date_range: &str,
    now: i64,
) {
    if completed_only {
        filters.where_sql.push("s.status = 'completed'".to_string());
    }
    if saved_only {
        filters
            .where_sql
            .push("s.first_file_id IS NOT NULL".to_string());
    }
    if !axis_count.is_empty() && axis_count != "all" {
        if let Ok(value) = axis_count.parse::<i64>() {
            if (1..=3).contains(&value) {
                filters.where_sql.push("s.axis_count = ?".to_string());
                filters.params.push(SqlParam::I64(value));
            }
        }
    }
    if !date_range.is_empty() && date_range != "all" {
        let sec = match date_range {
            "today" => Some(86_400),
            "week" => Some(7 * 86_400),
            "month" => Some(30 * 86_400),
            _ => None,
        };
        if let Some(sec) = sec {
            filters.where_sql.push("s.created_at >= ?".to_string());
            filters.params.push(SqlParam::I64(now - sec));
        }
    }
}

async fn load_reference(
    pool: &SqlitePool,
    ref_id: Option<&str>,
    keys: &[String],
) -> Result<Option<(SweepReference, Vec<String>)>, sqlx::Error> {
    if ref_id.is_none() || keys.is_empty() {
        return Ok(None);
    }
    let ref_id = ref_id.unwrap_or_default();
    let Some(row) = sqlx::query("SELECT * FROM sweeps WHERE id = ?")
        .bind(ref_id)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };
    let axes = sqlx::query(
        "SELECT axis_index, param FROM sweep_axes WHERE sweep_id = ? ORDER BY axis_index",
    )
    .bind(ref_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| row.get::<String, _>("param"))
    .collect::<Vec<_>>();
    Ok(Some((
        SweepReference {
            bridge: row.try_get::<Option<String>, _>("bridge").ok().flatten(),
            checkpoint: row
                .try_get::<Option<String>, _>("checkpoint")
                .ok()
                .flatten(),
            vae: row.try_get::<Option<String>, _>("vae").ok().flatten(),
            sampler: row.try_get::<Option<String>, _>("sampler").ok().flatten(),
            prompt_template: row
                .try_get::<Option<String>, _>("prompt_template")
                .ok()
                .flatten(),
            negative_template: row
                .try_get::<Option<String>, _>("negative_template")
                .ok()
                .flatten(),
            width: row.try_get::<Option<i64>, _>("width").ok().flatten(),
            height: row.try_get::<Option<i64>, _>("height").ok().flatten(),
            base_seed: row.try_get::<Option<i64>, _>("base_seed").ok().flatten(),
            steps: row.try_get::<Option<i64>, _>("steps").ok().flatten(),
            cfg: row.try_get::<Option<f64>, _>("cfg").ok().flatten(),
        },
        axes,
    )))
}

fn bind_params<'q>(
    mut query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    params: &'q [SqlParam],
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    for param in params {
        query = match param {
            SqlParam::I64(value) => query.bind(*value),
            SqlParam::F64(value) => query.bind(*value),
            SqlParam::String(value) => query.bind(value),
        };
    }
    query
}

async fn query_history(
    pool: &SqlitePool,
    params: &HashMap<String, String>,
) -> Result<(Vec<Value>, i64), sqlx::Error> {
    let limit = parse_history_limit(params.get("limit"));
    let keys = match_keys(params.get("match"));
    let mut filters = SweepHistoryFilters {
        where_sql: vec!["1=1".to_string()],
        params: Vec::new(),
    };
    if let Some((reference, axes)) =
        load_reference(pool, params.get("ref").map(String::as_str), &keys).await?
    {
        append_reference_filters(
            &mut filters,
            &reference,
            &axes,
            &keys,
            params
                .get("tol_steps")
                .map(String::as_str)
                .unwrap_or("exact"),
            params.get("tol_cfg").map(String::as_str).unwrap_or("exact"),
        );
    }
    append_constraint_filters(
        &mut filters,
        params.get("completed_only").is_some_and(|v| v == "1"),
        params.get("saved_only").is_some_and(|v| v == "1"),
        params
            .get("axis_count")
            .map(String::as_str)
            .unwrap_or("all"),
        params
            .get("date_range")
            .map(String::as_str)
            .unwrap_or("all"),
        unix_now(),
    );
    let sql = format!(
        "SELECT s.*, (SELECT GROUP_CONCAT(a.param, ',') FROM sweep_axes a
         WHERE a.sweep_id = s.id ORDER BY a.axis_index) AS axes_params_csv
         FROM sweeps s WHERE {} ORDER BY s.created_at DESC, s.id LIMIT ?",
        filters.where_sql.join(" AND ")
    );
    let mut query = bind_params(sqlx::query(&sql), &filters.params);
    query = query.bind(limit);
    let rows = query.fetch_all(pool).await?;
    let entries = rows
        .into_iter()
        .map(|row| {
            let csv = row
                .try_get::<Option<String>, _>("axes_params_csv")
                .ok()
                .flatten();
            json!({
                "id": row.get::<String, _>("id"),
                "bridge": row.try_get::<Option<String>, _>("bridge").ok().flatten(),
                "base_seed": row.try_get::<Option<i64>, _>("base_seed").ok().flatten(),
                "created_at": row.try_get::<Option<i64>, _>("created_at").ok().flatten(),
                "prompt_template": row.try_get::<Option<String>, _>("prompt_template").ok().flatten(),
                "negative_template": row.try_get::<Option<String>, _>("negative_template").ok().flatten(),
                "checkpoint": row.try_get::<Option<String>, _>("checkpoint").ok().flatten(),
                "vae": row.try_get::<Option<String>, _>("vae").ok().flatten(),
                "sampler": row.try_get::<Option<String>, _>("sampler").ok().flatten(),
                "width": row.try_get::<Option<i64>, _>("width").ok().flatten(),
                "height": row.try_get::<Option<i64>, _>("height").ok().flatten(),
                "steps": row.try_get::<Option<i64>, _>("steps").ok().flatten(),
                "cfg": row.try_get::<Option<f64>, _>("cfg").ok().flatten(),
                "axis_count": row.try_get::<Option<i64>, _>("axis_count").ok().flatten(),
                "first_file_id": row.try_get::<Option<i64>, _>("first_file_id").ok().flatten(),
                "last_file_id": row.try_get::<Option<i64>, _>("last_file_id").ok().flatten(),
                "file_count": row.try_get::<Option<i64>, _>("file_count").ok().flatten(),
                "status": row.try_get::<Option<String>, _>("status").ok().flatten(),
                "updated_at": row.try_get::<Option<i64>, _>("updated_at").ok().flatten(),
                "axes_params": csv.map(|s| s.split(',').map(ToString::to_string).collect::<Vec<_>>()).unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    let total = sqlx::query_scalar("SELECT COUNT(*) AS n FROM sweeps")
        .fetch_one(pool)
        .await?;
    Ok((entries, total))
}

fn api_success_data(data: Value) -> Response {
    Json(json!({"ok": true, "error": null, "data": data})).into_response()
}

fn api_error(message: &str) -> Response {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"ok": false, "error": message})),
    )
        .into_response()
}

pub async fn history(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    match query_history(&state.db_read, &params).await {
        Ok((entries, total)) => api_success_data(json!({"entries": entries, "total": total})),
        Err(error) => {
            tracing::error!(?error, "sweeps history failed");
            api_error("Failed to load sweep history")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_history_limit_to_python_range() {
        assert_eq!(clamp_history_limit(-5), 1);
        assert_eq!(clamp_history_limit(0), 1);
        assert_eq!(clamp_history_limit(501), 500);
        assert_eq!(clamp_history_limit(50), 50);
    }

    #[test]
    fn tolerant_filter_uses_percent_epsilon() {
        let mut filters = SweepHistoryFilters::default();
        append_tolerant_filter(&mut filters, "s.cfg", Some(7.0), "10");
        assert_eq!(filters.where_sql, vec!["s.cfg BETWEEN ? AND ?"]);
        assert_eq!(filters.params, vec![SqlParam::F64(6.3), SqlParam::F64(7.7)]);
    }

    #[test]
    fn reference_and_constraint_filters_match_python_keys() {
        let reference = SweepReference {
            bridge: Some("bridge".to_string()),
            checkpoint: Some("ckpt".to_string()),
            vae: Some("vae".to_string()),
            sampler: Some("sampler".to_string()),
            prompt_template: Some("pos".to_string()),
            negative_template: Some("neg".to_string()),
            width: Some(512),
            height: Some(768),
            base_seed: Some(42),
            steps: Some(20),
            cfg: Some(7.0),
        };
        let keys = [
            "bridge",
            "checkpoint",
            "vae",
            "sampler",
            "positive",
            "negative",
            "resolution",
            "baseSeed",
            "steps",
            "cfg",
            "axisX",
            "axisY",
            "axisZ",
        ]
        .into_iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
        let axes = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        let mut filters = SweepHistoryFilters::default();
        append_reference_filters(&mut filters, &reference, &axes, &keys, "exact", "10");
        append_constraint_filters(&mut filters, true, true, "2", "week", 1_000_000);

        assert!(filters.where_sql.contains(&"s.bridge = ?".to_string()));
        assert!(filters
            .where_sql
            .contains(&"s.prompt_template = ?".to_string()));
        assert!(filters
            .where_sql
            .contains(&"s.width = ? AND s.height = ?".to_string()));
        assert!(filters.where_sql.contains(&"s.steps = ?".to_string()));
        assert!(filters
            .where_sql
            .contains(&"s.cfg BETWEEN ? AND ?".to_string()));
        assert_eq!(
            filters
                .where_sql
                .iter()
                .filter(|part| part.starts_with("EXISTS (SELECT 1 FROM sweep_axes"))
                .count(),
            3
        );
        assert!(filters
            .where_sql
            .contains(&"s.status = 'completed'".to_string()));
        assert!(filters
            .where_sql
            .contains(&"s.first_file_id IS NOT NULL".to_string()));
        assert!(filters.where_sql.contains(&"s.axis_count = ?".to_string()));
        assert!(filters.where_sql.contains(&"s.created_at >= ?".to_string()));
    }
}
