// Development-only check for the two tables' shared copy interaction.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

let selection;
const handlers = {};
const messages = [];
const document = {
    createElement() { return {style: {}, select() { selection = this.value; }}; },
    body: {appendChild() {}, removeChild() {}},
    execCommand(command) { return command === 'copy'; }
};
const window = {innerWidth: 390};
vm.runInNewContext(fs.readFileSync('admin/js/cluster-domain-table.js', 'utf8'), {
    window, document, navigator: {}
});

const row = {domain: 'site.example', node_ips: '10.0.0.1,10.0.0.2'};
const columns = window.ClusterDomainTable.columns(true);
assert.match(columns.find((column) => column.field === 'node_ips').templet(row), /lay-event="domain-nodes"/);
assert.equal(window.ClusterDomainTable.columns(false).length + 1, columns.length);
const layer = {
    open(options) {
        assert.match(options.content, /复制全部 IP/);
        assert.equal(options.area[0], 'calc(100vw - 24px)');
        options.success({find(selector) {
            return {on(event, handler) { handlers[selector] = handler; }};
        }});
    },
    msg(value) { messages.push(value); }
};
assert.equal(window.ClusterDomainTable.handleEvent({event: 'domain-nodes', data: row}, layer), true);
handlers['[data-copy-all]']();
assert.equal(selection, '10.0.0.1\n10.0.0.2');
handlers['[data-copy-index]'].call({getAttribute() { return '1'; }});
assert.equal(selection, '10.0.0.2');
assert.equal(messages.length, 2);
assert.equal(window.ClusterDomainTable.handleEvent({event: 'policy', data: row}, layer), false);
console.log('DOMAIN_NODE_COPY_OK');
