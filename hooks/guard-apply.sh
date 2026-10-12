#!/bin/sh
# PreToolUse guard: asks the user before a Bash call runs `mailctl apply` with
# a flag that deletes or replaces live state, or without a reviewed saved plan.
# It never blocks on its own; the user decides.
input=$(cat)

printf '%s' "$input" | grep -Eq 'mailctl[^|;&]*[[:space:]]apply([[:space:]]|"|$)' || exit 0

reason=""
if printf '%s' "$input" | grep -Eq '[[:space:]]-{1,2}(prune|prune-mailboxes|replace-dns|yes)([=[:space:]]|"|$)'; then
	reason="mailctl apply with -prune, -prune-mailboxes, -replace-dns or -yes can delete mail or DNS records without a prompt."
elif ! printf '%s' "$input" | grep -Eq '[[:space:]]-{1,2}plan([=[:space:]]|"|$)'; then
	reason="mailctl apply without -plan applies whatever the live state is now, not a plan the user reviewed."
fi
[ -n "$reason" ] || exit 0

printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"%s"}}\n' "$reason"
