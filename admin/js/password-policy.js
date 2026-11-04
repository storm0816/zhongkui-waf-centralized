(function (root) {
    'use strict';
    var rules = [
        {label:'至少 8 个字符', test:function (value) { return value.length >= 8; }},
        {label:'至少 1 个字母（不区分大小写）', test:function (value) { return /[A-Za-z]/.test(value); }},
        {label:'至少 1 个数字（0-9）', test:function (value) { return /[0-9]/.test(value); }},
        {label:'至少 1 个特殊字符', test:function (value) { return /[!-/:-@\[-`{-~]/.test(value); }}
    ];
    function validate(value) {
        value = String(value || '');
        for (var i = 0; i < rules.length; i++) {
            if (!rules[i].test(value)) return '密码' + rules[i].label;
        }
        return '';
    }
    function render(container, value) {
        if (!container) return;
        value = String(value || '');
        container.innerHTML = '<div>密码须包含：</div>' + rules.map(function (rule) {
            var passed = rule.test(value);
            var state = value ? (passed ? 'passed' : 'failed') : 'pending';
            return '<div class="password-rule ' + state + '">' +
                (passed ? '✓' : '○') + ' ' + rule.label + '</div>';
        }).join('');
    }
    root.PasswordPolicy = {validate:validate, render:render};
})(window);
