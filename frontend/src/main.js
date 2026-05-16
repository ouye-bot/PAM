import { createApp } from 'vue'
import App from './App.vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import router from './router'

console.log('=== PAM Frontend Starting ===');
console.log('Base URL:', import.meta.env.BASE_URL);
console.log('API Proxy Target:', import.meta.env.VITE_API_TARGET || 'http://localhost:5000');

const app = createApp(App)
app.use(ElementPlus, { locale: zhCn })
app.use(router)

// 添加全局错误捕获
app.config.errorHandler = (err, instance, info) => {
  console.error('[Vue Global Error]', {
    error: err,
    component: instance?.$options?.name || 'Unknown',
    info: info
  });
  // 可以在这里添加错误上报逻辑
};

// 添加全局未捕获错误捕获
window.addEventListener('error', (event) => {
  console.error('[Global Error]', event.error);
});

// 添加全局未处理 Promise 拒绝捕获
window.addEventListener('unhandledrejection', (event) => {
  console.error('[Unhandled Promise Rejection]', event.reason);
});

app.mount('#app')

console.log('=== PAM Frontend Mounted ===');
console.log('=== Global Error Handlers Registered ===');