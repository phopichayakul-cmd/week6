#!/usr/bin/env bash
set -e
echo "Installing CBE204 Week 6 demo dependencies..."
(cd secure-api && npm install)
(cd vulnerable-api && npm install)
(cd session-api && npm install)
echo
echo "Start the APIs in separate terminals:"
echo "  cd secure-api && cp .env.example .env && npm start"
echo "  cd session-api && npm start"
echo "  cd vulnerable-api && npm start"
