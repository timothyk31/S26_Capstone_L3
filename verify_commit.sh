#!/bin/bash
# Verify files before committing to git

echo "======================================================================"
echo "Git Commit Verification"
echo "======================================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0

echo "Checking for sensitive files..."
echo ""

# Check for .env file
if git ls-files | grep -q "^\.env$"; then
    echo -e "${RED}✗ .env file is tracked! Remove it:${NC} git rm --cached .env"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ .env not tracked${NC}"
fi

# Check for inventory.yml with passwords
if git ls-files | grep -q "^inventory\.yml$"; then
    if git show :inventory.yml | grep -q "shipiA"; then
        echo -e "${RED}✗ inventory.yml contains passwords! Remove it:${NC} git rm --cached inventory.yml"
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${YELLOW}⚠ inventory.yml is tracked (make sure no passwords)${NC}"
    fi
else
    echo -e "${GREEN}✓ inventory.yml not tracked${NC}"
fi

# Check for SSH keys
if git ls-files | grep -E "\.(pem|key)$|id_rsa"; then
    echo -e "${RED}✗ SSH keys found in git!${NC}"
    git ls-files | grep -E "\.(pem|key)$|id_rsa"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ No SSH keys tracked${NC}"
fi

# Check for work directories
if git ls-files | grep -E "e2e_test_work|qa_loop_work|quick_test_work"; then
    echo -e "${RED}✗ Work directories found in git!${NC}"
    git ls-files | grep -E "e2e_test_work|qa_loop_work|quick_test_work" | head -5
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}✓ No work directories tracked${NC}"
fi

# Check for large scan files
if git ls-files | grep -E "scan.*\.xml$|.*_results\.xml$"; then
    echo -e "${YELLOW}⚠ Large XML scan files found (may be OK):${NC}"
    git ls-files | grep -E "scan.*\.xml$|.*_results\.xml$"
fi

echo ""
echo "Checking for required files..."
echo ""

# Check for templates
if git ls-files | grep -q "inventory.yml.template"; then
    echo -e "${GREEN}✓ inventory.yml.template present${NC}"
else
    echo -e "${RED}✗ Missing inventory.yml.template${NC}"
    ERRORS=$((ERRORS + 1))
fi

if git ls-files | grep -q "env.template"; then
    echo -e "${GREEN}✓ env.template present${NC}"
else
    echo -e "${YELLOW}⚠ Missing env.template${NC}"
fi

# Check for main scripts
REQUIRED_FILES=(
    "qa_loop.py"
    "openscap_cli.py"
    "parse_openscap.py"
    "test_end_to_end.py"
    "requirements.txt"
    "README.md"
    "TEAM_SETUP.md"
)

for file in "${REQUIRED_FILES[@]}"; do
    if git ls-files | grep -q "^$file$"; then
        echo -e "${GREEN}✓ $file present${NC}"
    else
        echo -e "${RED}✗ Missing $file${NC}"
        ERRORS=$((ERRORS + 1))
    fi
done

echo ""
echo "======================================================================"

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed! Safe to commit.${NC}"
    echo ""
    echo "Next steps:"
    echo "  git add *.py *.md *.sh requirements.txt *.template test_env/"
    echo "  git status  # Review what will be committed"
    echo "  git commit -m 'Add OpenSCAP QA loop implementation'"
    echo "  git push origin QA_PoC"
else
    echo -e "${RED}✗ Found $ERRORS issue(s). Fix before committing!${NC}"
    exit 1
fi

echo "======================================================================"

