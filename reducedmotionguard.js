'use strict';

// reducedmotionguard.js —— 减弱动效（prefers-reduced-motion）决策内核。
//
// 现代浏览器在系统开“减弱动态效果”后会 prefers-reduced-motion: reduce。
// Electron 壳如果忽略这个信号，会照放过渡动画/自动轮播，对视障和晕动用户不友好。
// 这里把“这次要不要砍动画/自动播放”收敛成纯函数，main/renderer 都能调。

const PRESET = {
	AUTO: 'auto',
	REDUCE: 'reduce',
	FULL: 'full',
};

// decideMotionPolicy 入参：
//   userPref    'auto'|'reduce'|'full'
//   systemReduce 布尔，是否检测到 prefers-reduced-motion: reduce
// 返回 { animations:'allow'|'disable', autoplay:'allow'|'block', reason }
function decideMotionPolicy(userPref, systemReduce) {
	const pref = String(userPref || PRESET.AUTO).toLowerCase();
	if (pref === PRESET.REDUCE || (pref === PRESET.AUTO && systemReduce)) {
		return {
			animations: 'disable',
			autoplay: 'block',
			reason: pref === PRESET.REDUCE ? 'user-forced-reduce' : 'system-reduce',
		};
	}
	return { animations: 'allow', autoplay: 'allow', reason: 'normal' };
}

// shouldSkipTransition 判断某个具体过渡类名要不要直接跳过。
// 在 reduce 模式下跳过耗时的位移动画，保留瞬时淡入。
function shouldSkipTransition(name, policy) {
	if (!policy || policy.animations !== 'disable') return false;
	const heavy = ['slide', 'zoom', 'flip', 'parallax', 'rotate'];
	return heavy.some((k) => String(name || '').toLowerCase().includes(k));
}

// mediaToBoolean 把 matchMedia 风格的入参安全转布尔。
function mediaToBoolean(mq) {
	if (mq && typeof mq.matches === 'boolean') return mq.matches;
	return Boolean(mq);
}

module.exports = {
	PRESET,
	decideMotionPolicy,
	shouldSkipTransition,
	mediaToBoolean,
};
