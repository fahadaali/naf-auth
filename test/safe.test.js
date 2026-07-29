// اختبارات تنقية `next` وتوابعها.
// عبر `node:test` و `node:assert` — لا حزمة اختبار خارجية، فالتبعيات تبقى صفراً.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  assertIdentifier,
  readCookie,
  safeNext,
  sessionCookie,
  timingSafeEqual,
} from '../src/safe.js';

test('safeNext يقبل المسارات الداخلية كما هي', () => {
  const accepted = [
    '/',
    '/posts',
    '/posts/42',
    '/posts?page=2',
    '/posts?page=2&sort=desc',
    '/تقارير',
    '/a/b/c/d',
    '/#anchor',
  ];
  for (const path of accepted) {
    assert.equal(safeNext(path), path, `يُتوقّع قبول ${path}`);
  }
});

test('safeNext يردّ العنوان المطلق إلى الجذر', () => {
  for (const path of ['https://evil.sa', 'http://evil.sa/x', 'HTTPS://evil.sa']) {
    assert.equal(safeNext(path), '/');
  }
});

test('safeNext يردّ العنوان البروتوكولي-النسبي إلى الجذر', () => {
  // `//evil.sa` يبدأ بشرطة مائلة لكنه موقع خارجي — أخطر صورة للثغرة.
  for (const path of ['//evil.sa', '//evil.sa/path', '///evil.sa']) {
    assert.equal(safeNext(path), '/');
  }
});

test('safeNext يردّ النقطتين الرأسيتين إلى الجذر', () => {
  for (const path of ['/x?q=a:b', 'javascript:alert(1)', '/redirect:evil']) {
    assert.equal(safeNext(path), '/');
  }
});

test('safeNext يردّ الشرطة العكسية إلى الجذر', () => {
  // المتصفح يطوي الشرطة العكسية إلى مائلة، فتصير `//evil.sa`.
  for (const path of ['/\\evil.sa', '/\\\\evil.sa', '/path\\to']) {
    assert.equal(safeNext(path), '/');
  }
});

test('safeNext يردّ محارف التحكّم إلى الجذر', () => {
  /* محرفُ تحكّمٍ حقيقي، لا نصُّه.
     كان هنا `'/\\tevil'` — وهو نصٌّ فيه شرطةٌ عكسية وحرفُ `t`، لا جدولة.
     فيردّه فحصُ الشرطة العكسية في `looksSafe` قبل أن يبلغ فحصَ محارف
     التحكّم الذي يليه، فيمرّ الاختبار والحارسُ لم يُنفَّذ قطّ.
     والبناء بـ`String.fromCharCode` يُبقي المقصود ظاهراً في السطر بدل أن
     يكون محرفاً غير مرئي يحذفه أول محرّر يمرّ عليه. */
  const ctrl = (code) => String.fromCharCode(code);
  const paths = [
    `/${ctrl(9)}evil`, // جدولة
    `/${ctrl(10)}evil`, // سطر جديد
    `/${ctrl(13)}evil`, // إرجاع
    `/a${ctrl(0)}b`, // NUL
    `/x${ctrl(127)}`, // DEL
  ];

  for (const path of paths) {
    // يثبت أن الفحص المقصود هو الذي ردّه: لا شرطة عكسية فيه تسبقه إليه.
    assert.ok(!path.includes('\\'), `المدخل يجب أن يخلو من الشرطة العكسية: ${JSON.stringify(path)}`);
    assert.equal(safeNext(path), '/');
  }
});

test('safeNext يردّ المسار النسبي وغير النصّ إلى الجذر', () => {
  for (const value of ['posts', '', null, undefined, 42, {}, [], true]) {
    assert.equal(safeNext(value), '/');
  }
});

test('safeNext لا يعدّ المسافة محرف تحكّم', () => {
  assert.equal(safeNext('/a b'), '/a b');
});

test('sessionCookie يحمل خصائص الاحتراز السادس ولا يحمل Domain', () => {
  const cookie = sessionCookie('naf_sid', 'abc123', 43200);
  assert.match(cookie, /^naf_sid=abc123;/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, /Path=\//);
  assert.match(cookie, /Max-Age=43200/);
  assert.doesNotMatch(cookie, /Domain=/);
});

test('readCookie يقرأ الاسم المطلوب دون ما يشابهه', () => {
  const request = {
    headers: { get: () => 'other=1; naf_sid=xyz; naf_sid_extra=nope' },
  };
  assert.equal(readCookie(request, 'naf_sid'), 'xyz');
  assert.equal(readCookie(request, 'missing'), null);
});

test('readCookie يعيد null بلا ترويسة', () => {
  assert.equal(readCookie({ headers: { get: () => null } }, 'naf_sid'), null);
});

test('readCookie يتخطّى نسخةً تالفة بالاسم نفسه ويكمل إلى الصحيحة', () => {
  /* المتصفّح يرسل نسخةً لكل `Domain` و`Path` كتبتها، ولا يقول أيُّها من
     أين. فنسخةٌ قديمة تعذّر فكّ ترميزها كانت تُنهي البحث وتعيد `null` —
     فيُخرَج صاحبُ جلسةٍ صحيحة، ولا يملك إصلاحها إلا بمسح كوكيّات الموقع. */
  const request = {
    headers: { get: () => 'naf_sid=%E0%A4%A; naf_sid=xyz' },
  };
  assert.equal(readCookie(request, 'naf_sid'), 'xyz');
});

test('readCookie يعيد null إن كانت كل النسخ تالفة', () => {
  const request = {
    headers: { get: () => 'naf_sid=%E0%A4%A; naf_sid=%ZZ' },
  };
  assert.equal(readCookie(request, 'naf_sid'), null);
});

test('timingSafeEqual يطابق المتساوي ويرفض ما عداه', () => {
  assert.equal(timingSafeEqual('abc', 'abc'), true);
  assert.equal(timingSafeEqual('abc', 'abd'), false);
  assert.equal(timingSafeEqual('abc', 'abcd'), false);
  assert.equal(timingSafeEqual('abc', null), false);
});

test('assertIdentifier يمنع إقحام اسم جدول أو عمود غير سليم', () => {
  assert.equal(assertIdentifier('users', 'جدول'), 'users');
  assert.equal(assertIdentifier('role_name', 'عمود'), 'role_name');
  for (const bad of ['users; DROP TABLE users', 'a-b', '1users', '', null, 'a b']) {
    assert.throws(() => assertIdentifier(bad, 'جدول'));
  }
});
