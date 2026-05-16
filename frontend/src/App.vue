<template>
  <router-view />
</template>

<script setup>
</script>

<style>
/* 全局CSS变量 */
:root {
  /* 主色调 */
  --primary-color: #38bdf8;
  --primary-dark: #0ea5e9;
  
  /* 状态色 */
  --success-color: #4ade80;
  --warning-color: #fbbf24;
  --danger-color: #ef4444;
  --purple-color: #a78bfa;
  
  /* 背景色 */
  --bg-primary: #f1f5f9;
  --bg-card: #ffffff;
  --bg-sidebar: #1e293b;
  --bg-sidebar-top: #0f172a;
  
  /* 文字色 */
  --text-primary: #1e293b;
  --text-secondary: #475569;
  --text-light: #64748b;
  --text-sidebar: #cbd5e1;
  
  /* 边框色 */
  --border-light: #e2e8f0;
  --border-dark: #334155;
  
  /* 间距 */
  --spacing-xs: 4px;
  --spacing-sm: 8px;
  --spacing-md: 16px;
  --spacing-lg: 20px;
  --spacing-xl: 32px;
  
  /* 圆角 */
  --border-radius-sm: 6px;
  --border-radius-md: 12px;
  --border-radius-lg: 16px;
  
  /* 阴影 */
  --shadow-sm: 0 2px 4px rgba(0,0,0,0.05);
  --shadow-md: 0 4px 12px rgba(0,0,0,0.05);
  --shadow-lg: 0 8px 24px rgba(0,0,0,0.1);
}

/* 全局样式 */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: "Microsoft YaHei", -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  color: var(--text-primary);
  background-color: var(--bg-primary);
  overflow: hidden;
}

/* Element Plus 覆盖样式 */
.el-menu--vertical {
  background-color: var(--bg-sidebar) !important;
}

.el-menu--vertical .el-menu-item {
  color: var(--text-sidebar) !important;
  font-size: 14px;
  transition: all 0.2s;
  margin: 4px 8px;
  border-radius: var(--border-radius-sm);
}

.el-menu--vertical .el-menu-item:hover {
  background: rgba(56, 189, 248, 0.15) !important;
  color: var(--primary-color) !important;
}

.el-menu--vertical .el-menu-item.is-active {
  background: rgba(56, 189, 248, 0.2) !important;
  color: var(--primary-color) !important;
}

/* 卡片样式增强 */
.el-card {
  border-radius: var(--border-radius-md);
  box-shadow: var(--shadow-md);
  border: 1px solid var(--border-light);
  background: var(--bg-card);
  overflow: hidden;
  transition: transform 0.3s, box-shadow 0.3s;
}

.el-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.el-card__header {
  border-bottom: 1px solid var(--border-light);
  padding: 14px 20px;
  background: #f8fafc;
  color: var(--text-primary);
  font-size: 16px;
  font-weight: bold;
}

.el-card__body {
  padding: 20px;
  color: var(--text-primary);
}

/* 按钮样式增强 */
.el-button {
  border-radius: var(--border-radius-sm);
  transition: all 0.3s;
  font-weight: 500;
}

.el-button--primary {
  background: var(--primary-color);
  border-color: var(--primary-color);
  color: white;
}

.el-button--primary:hover {
  background: var(--primary-dark);
  border-color: var(--primary-dark);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(56, 189, 248, 0.3);
}

.el-button--plain {
  border-color: rgba(56, 189, 248, 0.4);
  color: var(--primary-color);
  background: rgba(56, 189, 248, 0.08);
}

.el-button--plain:hover {
  border-color: var(--primary-color);
  background: rgba(56, 189, 248, 0.15);
}

.el-button--danger {
  background: var(--danger-color);
  border-color: var(--danger-color);
}

.el-button--danger:hover {
  background: #dc2626;
  border-color: #dc2626;
}

/* 表格样式增强 */
.el-table {
  border-radius: var(--border-radius-md);
  overflow: hidden;
  background: var(--bg-card) !important;
  border: 1px solid var(--border-light) !important;
  box-shadow: var(--shadow-sm);
}

.el-table th {
  background: #f8fafc !important;
  color: var(--text-secondary) !important;
  font-weight: 600 !important;
  border-bottom: 1px solid var(--border-light) !important;
}

.el-table td {
  background: var(--bg-card) !important;
  color: var(--text-primary) !important;
  border-bottom: 1px solid var(--border-light) !important;
}

.el-table--striped .el-table__body tr.el-table__row--striped td {
  background: #f8fafc !important;
}

.el-table__row:hover td {
  background: #f1f5f9 !important;
}

/* 输入框样式增强 */
.el-input__wrapper {
  background: var(--bg-card) !important;
  border: 1px solid var(--border-light) !important;
  border-radius: var(--border-radius-sm) !important;
}

.el-input__wrapper:hover {
  border-color: var(--primary-color) !important;
}

.el-input__wrapper.is-focus {
  border-color: var(--primary-color) !important;
  box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.15) !important;
}

.el-input__inner {
  color: var(--text-primary) !important;
}

/* 标签样式增强 */
.el-tag {
  border-radius: var(--border-radius-sm);
  font-size: 12px;
  padding: 2px 8px;
}

.el-tag--success {
  background: rgba(74, 222, 128, 0.15);
  border-color: rgba(74, 222, 128, 0.3);
  color: var(--success-color);
}

.el-tag--warning {
  background: rgba(251, 191, 36, 0.15);
  border-color: rgba(251, 191, 36, 0.3);
  color: var(--warning-color);
}

.el-tag--danger {
  background: rgba(239, 68, 68, 0.15);
  border-color: rgba(239, 68, 68, 0.3);
  color: var(--danger-color);
}

/* 时间线样式 */
.el-timeline-item__node {
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

/* 确保容器高度正确 */
html, body, #app {
  height: 100%;
  overflow: hidden;
}

/* 滚动条样式 */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

::-webkit-scrollbar-track {
  background: #f1f5f9;
  border-radius: var(--border-radius-sm);
}

::-webkit-scrollbar-thumb {
  background: #cbd5e1;
  border-radius: var(--border-radius-sm);
}

::-webkit-scrollbar-thumb:hover {
  background: #94a3b8;
}

/* 弹窗样式 */
.el-dialog {
  border-radius: var(--border-radius-md);
  box-shadow: var(--shadow-lg);
}

.el-dialog__header {
  border-bottom: 1px solid var(--border-light);
  padding: 20px;
}

.el-dialog__body {
  padding: 20px;
}

.el-dialog__footer {
  border-top: 1px solid var(--border-light);
  padding: 16px 20px;
}

/* 空状态样式 */
.el-empty__description {
  color: var(--text-light) !important;
}

.el-empty__image svg {
  opacity: 0.5 !important;
}
</style>