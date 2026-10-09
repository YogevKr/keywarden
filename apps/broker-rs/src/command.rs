use crate::{msg, OperationRequest, Result};
use std::collections::HashMap;

pub fn target(operation: &OperationRequest) -> Result<(String, Option<String>)> {
    let args = &operation.args;
    if args.iter().any(|arg| arg.contains(['\0', '\r', '\n'])) {
        return Err(msg("Invalid command arguments"));
    }
    let reference =
        args.first().map(String::as_str) == Some("read") && operation.operation == "read";
    let sub = match operation.operation.as_str() {
        "read" => "get",
        "list" => "list",
        "write" => "edit",
        "create" => "create",
        "delete" => "delete",
        _ => "",
    };
    if !reference
        && (sub.is_empty()
            || args.first().map(String::as_str) != Some("item")
            || args.get(1).map(String::as_str) != Some(sub))
    {
        return Err(msg(format!(
            "Command does not match the {} operation",
            operation.operation
        )));
    }
    let mut permitted = if reference {
        vec!["--no-newline"]
    } else {
        vec!["--vault", "--format"]
    };
    if !reference {
        match sub {
            "get" => permitted.extend(["--fields", "--reveal"]),
            "create" => permitted.extend(["--title", "--category"]),
            "delete" => permitted.push("--archive"),
            _ => (),
        }
    }
    let mut flags = HashMap::new();
    let mut positional = Vec::new();
    let mut i = if reference { 1 } else { 2 };
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        if !arg.starts_with('-') {
            positional.push(arg.as_str());
            continue;
        }
        let (key, inline) = arg
            .split_once('=')
            .map(|(k, v)| (k, Some(v)))
            .unwrap_or((arg, None));
        if !permitted.contains(&key) || flags.contains_key(key) {
            return Err(msg("Unsupported or duplicate command flag"));
        }
        let boolean = ["--no-newline", "--reveal", "--archive"].contains(&key);
        let value = if let Some(value) = inline {
            value
        } else if boolean {
            "true"
        } else {
            let value = args
                .get(i)
                .ok_or_else(|| msg("Invalid command flag value"))?;
            i += 1;
            value.as_str()
        };
        if value.is_empty() || value.starts_with('-') || (boolean && value != "true") {
            return Err(msg("Invalid command flag value"));
        }
        flags.insert(key, value);
    }
    if flags.get("--format").is_some_and(|value| *value != "json") {
        return Err(msg("Only JSON output is supported"));
    }
    let (vault, item) = if reference {
        if positional.len() != 1 || !positional[0].starts_with("op://") {
            return Err(msg("Read needs one secret reference"));
        }
        let parts: Vec<&str> = positional[0][5..].split('/').collect();
        if !(3..=4).contains(&parts.len())
            || parts
                .iter()
                .any(|part| part.is_empty() || part.contains(['%', '?', '#', '\\']))
        {
            return Err(msg("Invalid secret reference"));
        }
        if operation
            .field
            .as_ref()
            .is_some_and(|field| field != &parts[2..].join("/"))
        {
            return Err(msg("Field does not match command"));
        }
        (parts[0], Some(parts[1]))
    } else {
        let needs_item = ["get", "edit", "delete"].contains(&sub);
        let item = if needs_item {
            if positional.is_empty() || positional[0].is_empty() {
                return Err(msg("Command must name one item"));
            }
            Some(positional.remove(0))
        } else {
            None
        };
        let assignments = ["edit", "create"].contains(&sub);
        if !positional.is_empty()
            && (!assignments
                || positional
                    .iter()
                    .any(|arg| !arg.split_once('=').is_some_and(|(key, _)| !key.is_empty())))
        {
            return Err(msg("Unexpected command arguments"));
        }
        if operation
            .field
            .as_ref()
            .is_some_and(|field| flags.get("--fields").copied() != Some(field.as_str()))
        {
            return Err(msg("Field does not match command"));
        }
        (flags.get("--vault").copied().unwrap_or(""), item)
    };
    if vault.is_empty() || vault == "*" || operation.vault.as_deref() != Some(vault) {
        return Err(msg("Vault does not match command"));
    }
    if operation
        .item_id
        .as_ref()
        .is_some_and(|id| item != Some(id.as_str()))
    {
        return Err(msg("Item does not match command"));
    }
    Ok((vault.into(), item.map(str::to_owned)))
}
