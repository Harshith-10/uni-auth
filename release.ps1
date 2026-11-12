#!/usr/bin/env pwsh
# uni-auth release helper
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = "Stop"
cargo release-workspace @Arguments
