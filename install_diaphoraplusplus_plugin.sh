#!/usr/bin/env sh
# Install the Diaphora++ IDA plugin into ~/.idapro/plugins

set -e

repo_dir="$(cd "$(dirname "$0")" && pwd)"
plugin_src="${repo_dir}/plugin/diaphoraplusplus_plugin.py"
cfg_target_dir="${HOME}/.idapro/plugins"
cfg_target="${cfg_target_dir}/diaphoraplusplus_plugin.cfg"
plugin_target="${cfg_target_dir}/diaphoraplusplus_plugin.py"

mkdir -p "${cfg_target_dir}"

# Backup existing config if present
if [ -f "${cfg_target}" ]; then
  mv "${cfg_target}" "${cfg_target}.bak"
fi

cat > "${cfg_target}" <<EOF
[Diaphora++]
# Path to the Diaphora++ install directory (where diaphora_ida.py lives)
path=${repo_dir}
EOF

cp "${plugin_src}" "${plugin_target}"

echo "Installed Diaphora++ plugin to ${cfg_target_dir}"
echo "Restart IDA and look for 'Diaphora++' in the Plugins menu."
