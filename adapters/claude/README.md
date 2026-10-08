# Claude Code (Anthropic) integration

The repository root is a native Claude Code plugin. Its manifest is in
`.claude-plugin/plugin.json`; the marketplace catalog is in
`.claude-plugin/marketplace.json`; root `skills/` contains the review workflow;
and the plugin starts the bundled local MCP server with the plugin-root path.

Install it from GitHub:

```sh
claude plugin marketplace add aakash-code/unofficial-cwe-agentsec-kb
claude plugin install unofficial-cwe-agentsec-kb@unofficial-cwe-agentsec --scope project
```

For a manual MCP-only installation, run the following from the repository root:

```sh
claude mcp add --scope project --transport stdio unofficial_cwe_agentsec_kb -- python3 "$PWD/tools/agentsec.py" serve
claude mcp get unofficial_cwe_agentsec_kb
```

Review and approve project `.mcp.json` settings before use. The server is local
and read-only, but its review tool can inspect the path you provide. Run
`python3 tools/agentsec.py validate` before enabling it. For skill-only or
instruction-only use, follow the corresponding steps in the root README.
