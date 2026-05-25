# Rollback

If upgrade fails after file copy, restore from backup folder printed by `upgrade.sh`.

Example:

```bash
cd /opt/openresty/zhongkui-waf
BACKUP_DIR=/opt/openresty/zhongkui-waf-backup/upgrade_YYYYmmdd_HHMMSS

while read -r rel; do
  [ -z "$rel" ] && continue
  if [ -f "$BACKUP_DIR/$rel" ]; then
    sudo cp -f "$BACKUP_DIR/$rel" "/opt/openresty/zhongkui-waf/$rel"
    sudo chown webuser:users "/opt/openresty/zhongkui-waf/$rel"
    sudo chmod 644 "/opt/openresty/zhongkui-waf/$rel"
  fi
done < FILES.list

sudo /opt/openresty/nginx/sbin/nginx -t && sudo /opt/openresty/nginx/sbin/nginx -s reload
```
