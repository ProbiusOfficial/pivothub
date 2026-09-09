/* ============================================================
   全局通用组件：Toast 层 / 通用弹窗层
   ============================================================ */
(function (global) {
  'use strict';
  const S = PivotStore;

  global.Components = global.Components || {};

  global.Components['toast-layer'] = {
    name: 'ToastLayer',
    template: '#tpl-toast',
    setup() {
      return {
        toasts: Vue.computed(() => S.state.toasts),
        icon: global.icon,
      };
    },
  };

  global.Components['modal-layer'] = {
    name: 'ModalLayer',
    template: '#tpl-modal-layer',
    setup() {
      const modalTitle = Vue.computed(() => S.state.ui.modalTitle || '详情');
      const modalCode = Vue.computed(() => S.state.ui.modalCode || '');
      return {
        ui: S.state.ui,
        modalTitle,
        modalCode,
        copy: S.copy,
      };
    },
  };
})(window);
