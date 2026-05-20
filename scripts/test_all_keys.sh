#!/bin/bash

# Combined API key validator — Heroku, Square, Twilio, Google
# Usage: ./test_all_keys.sh [sf_out_file] [output_dir]
#   sf_out_file : path to secretfinder output (default: sf_out.txt in CWD)
#   output_dir  : where to write key lists and valid_*.txt files (default: CWD)

SF_FILE="${1:-sf_out.txt}"
OUT_DIR="${2:-.}"

if [ ! -f "$SF_FILE" ]; then
    echo "[!] SecretFinder output file not found: $SF_FILE"
    exit 1
fi

mkdir -p "$OUT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}================================================${NC}"
echo -e "${BOLD}${CYAN}  API Key Validator — Combined${NC}"
echo -e "${DIM}  Source : $SF_FILE${NC}"
echo -e "${DIM}  Output : $OUT_DIR${NC}"
echo -e "${BOLD}${CYAN}================================================${NC}"
echo ""

# ── HEROKU ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}${MAGENTA}[*] === HEROKU ===${NC}"

grep "Heroku API KEY" "$SF_FILE" | awk '{print $NF}' > "$OUT_DIR/heroku_keys.txt"
echo -e "${CYAN}[*] Found $(wc -l < "$OUT_DIR/heroku_keys.txt") keys to test...${NC}"
echo ""

VALID=0; DEAD=0
while read key; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        https://api.heroku.com/account \
        -H "Authorization: Bearer $key" \
        -H "Accept: application/vnd.heroku+json; version=3")
    if [ "$RESPONSE" == "200" ]; then
        echo -e "${GREEN}${BOLD}[VALID]${NC} $key"
        echo "$key" >> "$OUT_DIR/valid_heroku_keys.txt"
        VALID=$((VALID + 1))
    else
        echo -e "${RED}[DEAD] ${NC} $key ${DIM}($RESPONSE)${NC}"
        DEAD=$((DEAD + 1))
    fi
    sleep 0.5
done < "$OUT_DIR/heroku_keys.txt"

echo ""
echo -e "${CYAN}[*] Heroku — ${GREEN}Valid: $VALID${NC} | ${RED}Dead: $DEAD${NC}"
[ $VALID -gt 0 ] && echo -e "${YELLOW}[*] Valid keys saved to $OUT_DIR/valid_heroku_keys.txt${NC}"
echo ""

# ── SQUARE ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}${MAGENTA}[*] === SQUARE ===${NC}"

grep "square_access_token" "$SF_FILE" | awk '{print $NF}' > "$OUT_DIR/square_keys.txt"
echo -e "${CYAN}[*] Found $(wc -l < "$OUT_DIR/square_keys.txt") tokens to test...${NC}"
echo ""

VALID=0; DEAD=0
while read token; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        https://connect.squareup.com/v2/merchants/me \
        -H "Authorization: Bearer $token" \
        -H "Square-Version: 2024-01-18")
    if [ "$RESPONSE" == "200" ]; then
        echo -e "${GREEN}${BOLD}[VALID]${NC} $token"
        echo "$token" >> "$OUT_DIR/valid_square_keys.txt"
        VALID=$((VALID + 1))
    else
        echo -e "${RED}[DEAD] ${NC} $token ${DIM}($RESPONSE)${NC}"
        DEAD=$((DEAD + 1))
    fi
    sleep 0.5
done < "$OUT_DIR/square_keys.txt"

echo ""
echo -e "${CYAN}[*] Square — ${GREEN}Valid: $VALID${NC} | ${RED}Dead: $DEAD${NC}"
[ $VALID -gt 0 ] && echo -e "${YELLOW}[*] Valid tokens saved to $OUT_DIR/valid_square_keys.txt${NC}"
echo ""

# ── TWILIO ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}${MAGENTA}[*] === TWILIO ===${NC}"

grep "twilio_account_sid" "$SF_FILE" | awk '{print $NF}' \
    | grep -E "^AC[0-9a-f]{32}$" > "$OUT_DIR/twilio_sids.txt"

grep "twilio_auth_token" "$SF_FILE" | awk '{print $NF}' \
    | grep -E "^[0-9a-f]{32}$" > "$OUT_DIR/twilio_tokens.txt"

echo -e "${CYAN}[*] Real-looking Account SIDs : $(wc -l < "$OUT_DIR/twilio_sids.txt")${NC}"
echo -e "${CYAN}[*] Real-looking Auth Tokens  : $(wc -l < "$OUT_DIR/twilio_tokens.txt")${NC}"
echo ""

SID_COUNT=$(wc -l < "$OUT_DIR/twilio_sids.txt")
TOK_COUNT=$(wc -l < "$OUT_DIR/twilio_tokens.txt")

VALID=0; DEAD=0
if [ "$SID_COUNT" -gt 0 ] && [ "$TOK_COUNT" -gt 0 ]; then
    mapfile -t SIDS < "$OUT_DIR/twilio_sids.txt"
    mapfile -t TOKS < "$OUT_DIR/twilio_tokens.txt"
    for sid in "${SIDS[@]}"; do
        for tok in "${TOKS[@]}"; do
            RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
                "https://api.twilio.com/2010-04-01/Accounts/$sid.json" \
                -u "$sid:$tok")
            if [ "$RESPONSE" == "200" ]; then
                echo -e "${GREEN}${BOLD}[VALID]${NC} SID=$sid  TOKEN=$tok"
                echo "$sid:$tok" >> "$OUT_DIR/valid_twilio_keys.txt"
                VALID=$((VALID + 1))
            else
                echo -e "${RED}[DEAD] ${NC} SID=$sid  TOKEN=$tok ${DIM}($RESPONSE)${NC}"
                DEAD=$((DEAD + 1))
            fi
            sleep 0.5
        done
    done
else
    echo -e "${YELLOW}[*] Skipping validation — need both Account SIDs and Auth Tokens${NC}"
fi

echo ""
echo -e "${CYAN}[*] Twilio — ${GREEN}Valid: $VALID${NC} | ${RED}Dead: $DEAD${NC}"
[ $VALID -gt 0 ] && echo -e "${YELLOW}[*] Valid pairs saved to $OUT_DIR/valid_twilio_keys.txt${NC}"
echo ""

# ── GOOGLE ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}${MAGENTA}[*] === GOOGLE ===${NC}"

grep "google_api" "$SF_FILE" | awk '{print $NF}' \
    | grep -E "^AIza[0-9A-Za-z_-]{35}$" > "$OUT_DIR/google_keys.txt"

echo -e "${CYAN}[*] Real-looking Google API keys: $(wc -l < "$OUT_DIR/google_keys.txt")${NC}"
echo ""

VALID=0; DEAD=0
while read key; do
    RESPONSE=$(curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=London&key=$key")
    STATUS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)

    if [ "$STATUS" == "OK" ] || [ "$STATUS" == "ZERO_RESULTS" ]; then
        echo -e "${GREEN}${BOLD}[VALID]${NC} $key ${DIM}(status: $STATUS)${NC}"
        echo "$key" >> "$OUT_DIR/valid_google_keys.txt"
        VALID=$((VALID + 1))

        echo -e "  ${BLUE}[>] Checking other APIs...${NC}"
        YT=$(curl -s -o /dev/null -w "%{http_code}" \
            "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=$key")
        echo -e "  ${DIM}YouTube API : ${NC}$YT"

        PL=$(curl -s -o /dev/null -w "%{http_code}" \
            "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=0,0&radius=1&key=$key")
        echo -e "  ${DIM}Places API  : ${NC}$PL"

        FB=$(curl -s -o /dev/null -w "%{http_code}" \
            "https://firebase.googleapis.com/v1beta1/projects?key=$key")
        echo -e "  ${DIM}Firebase    : ${NC}$FB"

    elif [ "$STATUS" == "REQUEST_DENIED" ]; then
        echo -e "${RED}[DEAD] ${NC} $key ${DIM}(denied)${NC}"
        DEAD=$((DEAD + 1))
    else
        echo -e "${RED}[DEAD] ${NC} $key ${DIM}(status: $STATUS)${NC}"
        DEAD=$((DEAD + 1))
    fi
    sleep 0.5
done < "$OUT_DIR/google_keys.txt"

echo ""
echo -e "${CYAN}[*] Google — ${GREEN}Valid: $VALID${NC} | ${RED}Dead: $DEAD${NC}"
[ $VALID -gt 0 ] && echo -e "${YELLOW}[*] Valid keys saved to $OUT_DIR/valid_google_keys.txt${NC}"
echo ""
echo -e "${BOLD}${CYAN}================================================${NC}"
echo -e "${BOLD}${CYAN}  All checks complete.${NC}"
echo -e "${BOLD}${CYAN}================================================${NC}"
