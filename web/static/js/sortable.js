// Reorderable lists for edit mode: drag an item by its handle (mouse, pen or touch), or focus the
// handle and use the arrow keys. Works for vertical lists and wrapping grids alike.

/**
 * @param {HTMLElement} container  parent of the items
 * @param {object} o
 * @param {string} o.items     selector of the direct children that can be moved
 * @param {string} o.handle    selector of the drag handle inside an item
 * @param {() => boolean} [o.enabled]  only drag while this returns true (edit mode)
 * @param {(order: string[]) => void} [o.onChange]  called with the items' data-key values after a move
 * @returns {() => void} detach
 */
export function sortable(container, { items, handle, enabled = () => true, onChange }) {
  let drag = null; // {item, pointerId}

  const list = () => [...container.children].filter((c) => c.matches(items));
  const own = (el) => { const it = el && el.closest(items); return it && it.parentElement === container ? it : null; };
  const changed = () => { if (onChange) onChange(list().map((x) => x.dataset.key)); };

  function onDown(e) {
    const hd = e.target.closest(handle);
    if (!hd || !container.contains(hd) || !enabled() || e.button > 0) return;
    const item = own(hd);
    if (!item) return;
    e.preventDefault();
    drag = { item, pointerId: e.pointerId, moved: false };
    item.classList.add('dragging');
    container.classList.add('sorting');
    try { hd.setPointerCapture(e.pointerId); } catch (err) { /* not capturable */ }
  }
  function onMove(e) {
    if (!drag || e.pointerId !== drag.pointerId) return;
    e.preventDefault();
    const under = document.elementFromPoint(e.clientX, e.clientY);
    const over = own(under);
    if (!over || over === drag.item) return;
    const all = list();
    const from = all.indexOf(drag.item), to = all.indexOf(over);
    if (from < to) over.after(drag.item); else over.before(drag.item);
    drag.moved = true;
  }
  function onUp(e) {
    if (!drag || e.pointerId !== drag.pointerId) return;
    drag.item.classList.remove('dragging');
    container.classList.remove('sorting');
    const moved = drag.moved;
    drag = null;
    if (moved) changed();
  }
  function onKey(e) {
    const hd = e.target.closest(handle);
    if (!hd || !enabled()) return;
    const item = own(hd);
    if (!item) return;
    const back = e.key === 'ArrowUp' || e.key === 'ArrowLeft', fwd = e.key === 'ArrowDown' || e.key === 'ArrowRight';
    if (!back && !fwd && e.key !== 'Home' && e.key !== 'End') return;
    e.preventDefault();
    const all = list(), i = all.indexOf(item);
    if (e.key === 'Home') { if (i > 0) all[0].before(item); else return; }
    else if (e.key === 'End') { if (i < all.length - 1) all[all.length - 1].after(item); else return; }
    else if (back) { if (i > 0) all[i - 1].before(item); else return; }
    else if (i < all.length - 1) all[i + 1].after(item); else return;
    hd.focus();
    changed();
  }

  container.addEventListener('pointerdown', onDown);
  container.addEventListener('pointermove', onMove);
  container.addEventListener('pointerup', onUp);
  container.addEventListener('pointercancel', onUp);
  container.addEventListener('keydown', onKey);
  return () => {
    container.removeEventListener('pointerdown', onDown);
    container.removeEventListener('pointermove', onMove);
    container.removeEventListener('pointerup', onUp);
    container.removeEventListener('pointercancel', onUp);
    container.removeEventListener('keydown', onKey);
  };
}

/** Sorts `list` by the position of keyOf(x) in `order`; items not in `order` keep their relative order, after the others. */
export function applyOrder(list, order, keyOf) {
  if (!order || !order.length) return list.slice();
  const pos = new Map(order.map((k, i) => [String(k), i]));
  return list.map((x, i) => [x, i]).sort((a, b) => {
    const pa = pos.has(String(keyOf(a[0]))) ? pos.get(String(keyOf(a[0]))) : Infinity;
    const pb = pos.has(String(keyOf(b[0]))) ? pos.get(String(keyOf(b[0]))) : Infinity;
    return pa !== pb ? pa - pb : a[1] - b[1];
  }).map((x) => x[0]);
}
