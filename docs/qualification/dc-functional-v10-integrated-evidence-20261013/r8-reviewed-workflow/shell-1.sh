sudo apt-get update
sudo apt-get install -y --no-install-recommends poppler-utils acl libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core fonts-noto-cjk
test -x /usr/bin/pdftoppm
/usr/bin/pdftoppm -v
