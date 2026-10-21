(function (global) {
    'use strict';
    function escape(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) {
            return {'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c];
        });
    }
    function metric(field, approximate) {
        return function (row) {
            var value = row[field];
            if (row.domain === '*' || value == null) return '-';
            return (approximate ? '≈ ' : '') + Number(value).toLocaleString('en-US');
        };
    }
    function nodeIps(row) {
        if (row.domain === '*') return [];
        return String(row.node_ips || '').split(',').map(function (ip) { return ip.trim(); }).filter(Boolean);
    }
    function copyText(value, onSuccess, onFailure) {
        function fallback() {
            var input = document.createElement('textarea');
            input.value = value;
            input.style.position = 'fixed';
            input.style.opacity = '0';
            document.body.appendChild(input);
            input.select();
            var copied = false;
            try { copied = document.execCommand('copy'); } catch (e) { copied = false; } finally { document.body.removeChild(input); }
            (copied ? onSuccess : onFailure)();
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(value).then(onSuccess, fallback);
        } else {
            fallback();
        }
    }
    function showNodes(row, layer) {
        var nodes = nodeIps(row);
        var content = '<div class="domain-node-details">';
        if (nodes.length) {
            content += '<div class="domain-node-toolbar"><span>共 ' + nodes.length + ' 个节点</span><button type="button" class="layui-btn layui-btn-sm" data-copy-all>复制全部 IP</button></div>';
            content += '<div class="domain-node-list">';
            nodes.forEach(function (ip, index) {
                content += '<div class="domain-node-item"><code>' + escape(ip) + '</code><button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-copy-index="' + index + '" aria-label="复制 ' + escape(ip) + '">复制</button></div>';
            });
            content += '</div>';
        } else {
            content += '<div class="domain-node-empty">暂无来源节点</div>';
        }
        content += '</div>';
        layer.open({
            type: 1,
            title: '来源节点 · ' + escape(row.domain),
            area: [window.innerWidth < 520 ? 'calc(100vw - 24px)' : '480px', 'auto'],
            content: content,
            success: function (panel) {
                function copied() { layer.msg('已复制'); }
                function failed() { layer.msg('复制失败，请选中 IP 手动复制'); }
                panel.find('[data-copy-all]').on('click', function () { copyText(nodes.join('\n'), copied, failed); });
                panel.find('[data-copy-index]').on('click', function () {
                    copyText(nodes[Number(this.getAttribute('data-copy-index'))], copied, failed);
                });
            }
        });
    }
    global.ClusterDomainTable = {
        handleEvent: function (event, layer) {
            if (event.event !== 'domain-nodes') return false;
            showNodes(event.data, layer);
            return true;
        },
        columns: function (editable) {
            var columns = [
                {field:'domain', title:'域名', minWidth:220},
                {field:'requests_1m', title:'1分钟请求', width:105, align:'right', templet:metric('requests_1m')},
                {field:'cc_hits_5m', title:'5分钟CC命中', width:115, align:'right', templet:metric('cc_hits_5m')},
                {field:'attack_count_24h', title:'24小时攻击请求', width:135, align:'right', templet:metric('attack_count_24h')},
                {field:'uv_24h', title:'24小时UV', width:125, align:'right', templet:metric('uv_24h', true)},
                {field:'requests_24h', title:'24小时访问(PV)', width:135, align:'right', templet:metric('requests_24h')},
                {field:'node_count', title:'节点数', width:75, align:'right'},
                {field:'node_ips', title:'来源节点', width:165, templet:function (row) {
                    var nodes = nodeIps(row);
                    if (!nodes.length) return row.domain === '*' ? '全部域名' : '-';
                    var text = nodes[0];
                    if (nodes.length > 1) text += ' +' + (nodes.length - 1);
                    return '<button type="button" class="domain-node-trigger" lay-event="domain-nodes" title="查看并复制来源节点 IP">' + escape(text) + '</button>';
                }},
                {title:'集群阈值', width:165, templet:function (row) {
                    return escape(row.threshold_value) + ' 次 / ' + escape(row.duration_seconds) + ' 秒（' + (row.policy_source === 'custom' ? '特例' : '默认') + '）';
                }},
                {field:'status', title:'状态', width:85, templet:function (row) {return row.domain === '*' ? '默认' : (row.status === 'active' ? '活跃' : '已停用');}},
                {field:'last_seen', title:'最后发现', width:170}
            ];
            if (editable) columns.push({title:'操作', toolbar:'#id-template-domain-bar', width:140});
            return columns;
        },
        note: 'UV 按来源 IP 跨节点去重估算（≈），每 30 秒更新缓存。UV / PV 为当前小时及此前 23 个小时；攻击请求为近 24 小时已入库攻击日志数。UV 从节点升级后开始积累。'
    };
})(window);
