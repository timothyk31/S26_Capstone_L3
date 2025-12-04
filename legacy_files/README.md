These files are files that were likely used at some point, but are no longer part of the main program that is run. These were kept in case a new teams want to look at them for reference or need any parts from them in the future.

## What lives in `legacy_files/`

- **Nessus remediation pipeline**

  - `agent.py`: LLM-based remediation suggester that reads `parsed_vulns.json` and writes `remediations.json`.
  - `parse_nessus.py`: Parses `.nessus` XML into `parsed_vulns.json`.
  - `run_pipeline.py`: CLI to run parsing + agent end-to-end.
  - `README_nessus.md`: Documentation for the Nessus pipeline.

- **OpenSCAP QA loop & E2E harness**

  - `qa_loop.py`: Iterative scan → remediate → rescan loop using OpenSCAP, the Nessus-style agent, and Ansible.
  - `test_end_to_end.py`: Interactive end-to-end test script wiring together OpenSCAP, the agent, and Ansible.

- **Examples, demos, and tools**
  - `run_adaptive.py`: Convenience wrapper that reads `inventory.yml` and runs `qa_agent_adaptive.py` with prompts for sudo password.
  - `test_pydantic_ai_demo.py`: Small `pydantic_ai` demo unrelated to the main product.
  - `tools/run_adaptive_direct.sh`: Example shell wrapper for running the adaptive agent (expects `SUDO_PASSWORD` in the environment).
  - `tools/setup_ssh_key.sh`: Example script for setting up SSH keys and an `inventory.yml` stub for lab environments.

> None of the modules in `legacy_files/` are required to run the primary adaptive OpenSCAP agent (`qa_agent_adaptive.py`). They are kept purely for reference and for future teams who may want to revisit the older designs.
