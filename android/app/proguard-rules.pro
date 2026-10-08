# Kenato release rules.
# Keep this file minimal. Add rules only when a dependency or verified runtime path requires them.

# Diagnostic enum names are a persisted, user-readable protocol within the local journal.
# Release R8 must not rename/unbox these fixed safe event codes.
-keep enum com.sl.kenato.diagnostics.M45DiagnosticEvent { *; }
