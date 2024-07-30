

FAQ:
What about Stratus Red Team?

Why not just plain CloudTrail?
=> doesn't allow to filter by user agent
=> would require getting all logs and filtering them out


```
grimoire run --stratus-red-team-attack-technique aws.defense-evasion.foobar
grimoire run --shell
```

More expectations:

```
grimoire run --shell --expect-
```