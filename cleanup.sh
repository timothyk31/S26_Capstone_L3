#!/bin/bash
echo "🧹 Cleaning buildtime artifacts..."

# OpenSCAP scan outputs
echo "  Removing OpenSCAP scan files..."
rm -f oscap_*.xml
rm -f oscap_*.html  
rm -f oscap_*.json
rm -f *_parsed.json
rm -f *_report.html

# Multi-agent pipeline outputs
echo "  Removing pipeline outputs..."
rm -rf reports/
rm -rf pipeline_work/
rm -rf work_dir/
rm -rf work_remedy_demo/

# Legacy single-agent outputs
echo "  Removing legacy outputs..."
rm -rf adaptive_qa_work/
rm -rf qa_loop_work/
rm -rf e2e_test_work/

# LLM debugging/logging files
echo "  Removing LLM logs..."
rm -f llm_mitm.txt
rm -f *_transcript*.json
rm -f *_prompt*.txt

# Temporary remediation files
echo "  Removing temporary files..."
rm -f *.yml.tmp
rm -f fix_*.json
rm -f verify_*.xml
rm -f verify_*.json

# Other temp/backup files
rm -f *.bak
rm -f *.tmp

echo "Buildtime artifacts removed."