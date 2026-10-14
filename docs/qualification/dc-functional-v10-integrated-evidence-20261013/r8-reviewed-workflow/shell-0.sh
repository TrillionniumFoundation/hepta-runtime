test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"
git archive --format=tar.gz HEAD > /tmp/hepta-runtime-source.tar.gz
