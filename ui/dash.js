/** SVG charts — colors/layout: styles.css (:root --dash-* + блок «Dash») */
const Dash = {
  colors: {
    grid: '#eceef2',
    axis: '#b8bcc6',
    muted: '#d8dbe2',
    blue: '#4451f5',
    red: '#ef3124',
    green: '#7FE789',
  },

  niceMax(raw) {
    if (raw <= 0) return 10;
    const exp = 10 ** Math.floor(Math.log10(raw));
    const n = raw / exp;
    let step = 10;
    if (n <= 1) step = 1;
    else if (n <= 2) step = 2;
    else if (n <= 5) step = 5;
    return step * exp;
  },

  renderLegend(el, series) {
    if (!el) return;
    el.innerHTML = series
      .map((s) => `<span><i style="background:${s.color}"></i> ${s.name}</span>`)
      .join('');
  },

  yTicks(max) {
    return [0, 1, 2, 3, 4].map((i) => Math.round(max - (max * i) / 4));
  },

  mountChart(container, { labels, yMax, plotSvg, ariaLabel = 'График' }) {
    const ticks = this.yTicks(yMax);
    container.innerHTML = `
      <div class="dash-chart__frame" role="img" aria-label="${ariaLabel}">
        <div class="dash-chart__ylabels" aria-hidden="true">
          ${ticks.map((t) => `<span>${t}</span>`).join('')}
        </div>
        <div class="dash-chart__plot">
          <svg viewBox="0 0 640 196" preserveAspectRatio="none">${plotSvg}</svg>
        </div>
        <div class="dash-chart__xlabels" aria-hidden="true">
          ${labels.map((l) => `<span>${l}</span>`).join('')}
        </div>
      </div>`;
  },

  plotGrid(W, H, pad) {
    const plotW = W - pad.left - pad.right;
    const plotH = H - pad.top - pad.bottom;
    let svg = '';
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (plotH * i) / 4;
      svg += `<line x1="${pad.left}" y1="${y}" x2="${W - pad.right}" y2="${y}" stroke="${this.colors.grid}" stroke-width="1"/>`;
    }
    svg += `<line x1="${pad.left}" y1="${pad.top + plotH}" x2="${W - pad.right}" y2="${pad.top + plotH}" stroke="${this.colors.axis}" stroke-width="1"/>`;
    return { svg, plotW, plotH, pad, W, H };
  },

  renderGroupedBars(container, { labels, series, highlightIndex }) {
    const W = 640;
    const H = 196;
    const pad = { top: 12, right: 12, bottom: 4, left: 8 };
    const max = this.niceMax(Math.max(...series.flatMap((s) => s.values)));
    const frame = this.plotGrid(W, H, pad);
    const n = labels.length;
    const groupW = frame.plotW / n;
    const barW = Math.min(14, (groupW - 8) / series.length);
    const gap = 4;
    const barH = (v) => Math.max(v > 0 ? 4 : 0, (v / max) * frame.plotH);

    let plotSvg = frame.svg;
    labels.forEach((_, gi) => {
      const gx = pad.left + gi * groupW + groupW / 2;
      const groupStart = gx - (series.length * barW + (series.length - 1) * gap) / 2;

      series.forEach((s, si) => {
        const v = s.values[gi];
        const h = barH(v);
        const x = groupStart + si * (barW + gap);
        const y = pad.top + frame.plotH - h;
        const color = highlightIndex === gi && si === 1 ? this.colors.red : s.color;
        plotSvg += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW}" height="${h.toFixed(1)}" rx="4" fill="${color}"/>`;
      });
    });

    this.mountChart(container, { labels, yMax: max, plotSvg });
  },

  renderDonut(container, segments) {
    const size = 120;
    const cx = 60;
    const cy = 60;
    const r = 46;
    const stroke = 14;
    const total = segments.reduce((a, s) => a + s.value, 0);
    const C = 2 * Math.PI * r;
    let offset = 0;
    let svg = `<svg viewBox="0 0 ${size} ${size}" role="img" aria-label="Круговая диаграмма">`;
    segments.forEach((seg) => {
      const len = (seg.value / total) * C;
      svg += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${seg.color}" stroke-width="${stroke}" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 ${cx} ${cy})"/>`;
      offset += len;
    });
    svg += '</svg>';
    container.insertAdjacentHTML('afterbegin', svg);
  },

  renderHBars(container, items) {
    const max = Math.max(...items.map((i) => i.value));
    container.innerHTML = items
      .map((item) => {
        const pct = Math.min(100, Math.max(0, Math.round((item.value / max) * 100)));
        return `<div class="dash-hbar">
            <div class="dash-hbar__top">
              <span class="dash-hbar__label">${item.label}</span>
              <span class="dash-hbar__val">${item.value.toLocaleString('ru-RU')}</span>
            </div>
            <div class="dash-hbar__track"><div class="dash-hbar__fill" style="width:${pct}%"></div></div>
          </div>`;
      })
      .join('');
  },

  _plotCoords(labels, series, W = 640, H = 196) {
    const pad = { top: 12, right: 12, bottom: 4, left: 8 };
    const plotW = W - pad.left - pad.right;
    const plotH = H - pad.top - pad.bottom;
    const flat = series.flatMap((s) => s.values);
    const max = this.niceMax(Math.max(...flat));
    const n = labels.length;
    const step = n > 1 ? plotW / (n - 1) : plotW;
    const xAt = (i) => pad.left + i * step;
    const yAt = (v) => pad.top + plotH - (v / max) * plotH;
    const frame = this.plotGrid(W, H, pad);
    return { ...frame, max, xAt, yAt, pad, plotH };
  },

  renderLine(container, { labels, series, highlightIndex }) {
    const coords = this._plotCoords(labels, series);
    let plotSvg = coords.svg;

    series.forEach((s) => {
      const pts = s.values.map((v, i) => `${coords.xAt(i).toFixed(1)},${coords.yAt(v).toFixed(1)}`).join(' ');
      plotSvg += `<polyline points="${pts}" fill="none" stroke="${s.color}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>`;
      s.values.forEach((v, i) => {
        const isPeak = highlightIndex === i;
        plotSvg += `<circle cx="${coords.xAt(i).toFixed(1)}" cy="${coords.yAt(v).toFixed(1)}" r="${isPeak ? 5 : 3.5}" fill="${isPeak ? this.colors.red : s.color}"/>`;
      });
    });

    this.mountChart(container, { labels, yMax: coords.max, plotSvg });
  },

  renderArea(container, { labels, series }) {
    const coords = this._plotCoords(labels, series);
    let plotSvg = coords.svg;
    const baseline = coords.pad.top + coords.plotH;

    series.forEach((s) => {
      const top = s.values.map((v, i) => `${coords.xAt(i).toFixed(1)},${coords.yAt(v).toFixed(1)}`).join(' L ');
      const area = `M ${coords.xAt(0).toFixed(1)},${baseline} L ${top} L ${coords.xAt(labels.length - 1).toFixed(1)},${baseline} Z`;
      plotSvg += `<path d="${area}" fill="${s.color}" fill-opacity="0.18"/>`;
      const points = s.values
        .map((v, i) => `${coords.xAt(i).toFixed(1)},${coords.yAt(v).toFixed(1)}`)
        .join(' ');
      plotSvg += `<polyline points="${points}" fill="none" stroke="${s.color}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>`;
    });

    this.mountChart(container, { labels, yMax: coords.max, plotSvg });
  },

  renderStackedBars(container, { labels, series, highlightIndex }) {
    const W = 640;
    const H = 196;
    const pad = { top: 12, right: 12, bottom: 4, left: 8 };
    const totals = labels.map((_, i) => series.reduce((sum, s) => sum + s.values[i], 0));
    const max = this.niceMax(Math.max(...totals));
    const frame = this.plotGrid(W, H, pad);
    const n = labels.length;
    const groupW = frame.plotW / n;
    const barW = Math.min(22, groupW - 10);

    let plotSvg = frame.svg;
    labels.forEach((_, gi) => {
      const gx = pad.left + gi * groupW + groupW / 2;
      const x = gx - barW / 2;
      let stackY = pad.top + frame.plotH;

      series.forEach((s, si) => {
        const v = s.values[gi];
        const h = Math.max(v > 0 ? 4 : 0, (v / max) * frame.plotH);
        stackY -= h;
        const color = highlightIndex === gi && si === series.length - 1 ? this.colors.red : s.color;
        plotSvg += `<rect x="${x.toFixed(1)}" y="${stackY.toFixed(1)}" width="${barW}" height="${h.toFixed(1)}" rx="${si === 0 ? 4 : 0}" fill="${color}"/>`;
      });
    });

    this.mountChart(container, { labels, yMax: max, plotSvg });
  },
};
