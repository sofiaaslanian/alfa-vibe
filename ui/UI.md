<ui version="3">

<structure>
  <dir>ui/</dir> — весь UI в одной папке
  <file>UI.md</file> — rules for AI agents
  <file>styles.css</file> — fonts + tokens + shell + dash classes
  <file>dash.js</file> — SVG-графики (объект Dash)
  <file>ui-patterns.html</file> — живая галерея UI-паттернов (reference)
  <file>ui-creative.html</file> — мягкие UI-акценты: hero metric, icon tiles, спокойные анимации (без 3D/shadow)
  <file>charts-dashboard.html</file> — дашборд с графиками (reference)
  <file>employee-portal.html</file> — личный кабинет сотрудника (internal HR platform)
  <file>icons.zip</file> — 305 PNG + alfa-logo (~770 KB)
  <file>photos.zip</file> — maria-profile + 5 guests (~3.3 MB)
  <dir>fonts/</dir> — woff2 (gitignored)
  <setup>после clone — см. &lt;assets-setup&gt;</setup>
</structure>

<assets-setup>
  <when>Один раз после clone, перед вайбкодингом с иконками/фото</when>
  <commands>
    cd ui
    unzip -q -o icons.zip -d icons
    unzip -q -o photos.zip -d photos
  </commands>
  <git>В git только icons.zip + photos.zip — ui/icons/ и ui/photos/ в gitignore (не сотни строк в diff)</git>
  <paths-after-unzip>ui/icons/… · ui/photos/maria-profile.png · ui/photos/guests/ak.png</paths-after-unzip>
</assets-setup>

<mode>internal product — default for hackathon. Not marketing landing.</mode>

<brand preserved="always">
  <item>Font — Styrene A, fallback system-ui</item>
  <item>Page background — white #ffffff</item>
  <item>Content panels — gray #f2f3f5 on white (class .card)</item>
  <item>Primary action — red #ef3124 (.btn--primary)</item>
  <item>Secondary accent — blue #4451f5 (links, badges, at-risk, .sidenav__badge)</item>
  <item>Success — green #7fe789 (.badge--ok, .health--ok, .dot--ok)</item>
  <item>No orange — never #de6a00 or orange chips; pending/at-risk → blue</item>
  <item>Text — #0b1f35, secondary rgba(11,31,53,0.6)</item>
  <item>No shadows — no box-shadow anywhere; depth via bg color (#eceef2 canvas vs white cards vs #f2f3f5 controls)</item>
</brand>

<source>
  Alfa visual language (alfabank.ru tokens) applied to internal tools —
  sidebar app shell, task-first layouts, functional density.
  Reference vibe: Linear, Stripe Dashboard, LiteLLM admin — not travel landing.
</source>

<layout shell="required">
  <preferred>.shell → .sidenav + .main — floating cards on gray canvas #eceef2 (product UI default)</preferred>
  <legacy>header (.header--app) → .app-shell → .sidebar + .app-main — flat sidebar, use only if no .shell</legacy>
  <canvas>.shell — padding 16px, gap 16px, bg #eceef2 (--alfa-shell-bg)</canvas>
  <sidenav>260px white card, radius 28px, no shadow — see &lt;sidenav&gt; block</sidenav>
  <main>.main — white content card, .main__top (title + .main__toolbar), then page content</main>
  <width>content flows inside .main — tables/boards may go wide</width>
</layout>

<sidenav required="true">
  <structure>
    .sidenav → .sidenav__brand (.sidenav__logo) → .sidenav__scroll → .sidenav__group × N
    each group: .sidenav__label + .sidenav__nav → .sidenav__link × N
  </structure>
  <logo>&lt;img class="sidenav__logo" src="ui/icons/alfa-logo.png" alt="Альфа-Банк"&gt; — из icons.zip после unzip</logo>
  <groups>Uppercase section labels — .sidenav__label (Пропуска, Мониторинг, Настройки…)</groups>
  <link>
    .sidenav__link — flex row: .ui-icon 20px + .sidenav__link-text + optional .sidenav__badge
    every nav item must have a semantic or neutral .ui-icon — never text-only
  </link>
  <active>.sidenav__link--active — red pill #ef3124, white text, white icon (filter invert)</active>
  <inactive>gray text rgba(11,31,53,0.6), icon opacity 0.55</inactive>
  <hover>inactive only — bg #f2f3f5, no animation</hover>
  <badge>.sidenav__badge — blue #4451f5 count pill on link; on active → white bg, dark-red text</badge>
  <motion>transition: none on links — instant color/bg swap, no sliding indicator</motion>
  <forbidden-in-sidenav>dark promo cards at bottom · sliding pill animation · delayed active state · emoji/icon-chip placeholders</forbidden-in-sidenav>
</sidenav>

<main-toolbar>
  <structure>.main__top — .main__title left · .main__toolbar right · затем контент без промежуточных badge-рядов</structure>
  <spacing-after-head>.main__top margin-bottom 28px — воздух между шапкой и контентом (не меньше)</spacing-after-head>
  <toolbar>.main__toolbar — .main__icon-btn (Search, Notification) + .main__profile</toolbar>
  <icon-btn>44px gray circle #f2f3f5 (.main__icon-btn), .ui-icon 20px — Search- / Notification- PNG</icon-btn>
  <notify>.main__notify-dot — red 8px badge on bell button</notify>
  <profile>.main__profile-photo — photos/maria-profile.png · Мария Кузнецова / Security · круг 44px, object-fit cover</profile>
  <no-legacy>Do not use .main__user text-only or .main__avatar initials — use photo + two-line profile</no-legacy>
</main-toolbar>

<photos required="true">
  <archive>ui/photos.zip → распаковать в ui/photos/</archive>
  <setup>см. &lt;assets-setup&gt;</setup>
  <profile>photos/maria-profile.png — toolbar (Мария Кузнецова)</profile>
  <guests>photos/guests/ak|yt|pm|ev|is.png — .guest-avatar 36px</guests>
  <mapping>
    ak → Alex Klein · yt → Yuki Tanaka · pm → Pavel Morozov · ev → Elena Volkova · is → Ivan Smirnov
  </mapping>
  <forbidden>icon-chip с инициалами · stock avatars · /tmp/ paths</forbidden>
</photos>

<ux principles>
  <item>Task-first — screen opens with what user must do, not slogan</item>
  <item>One primary action per view — one .btn--primary (red), rest .btn--secondary</item>
  <item>Input → action → output — top to bottom: paste data, run, read result</item>
  <item>Status in context — .health / .dot-row в таблицах и карточках; не строка .badge под шапкой</item>
  <item>Feedback — loading label on button, streaming cursor, success badge when done</item>
  <item>Functional density — smaller titles, tighter spacing than landing; no hero blocks</item>
  <item>Panels are not clickable — .card has no hover shift; use .card--interactive only if needed</item>
  <item>Monospace for machine data — logs, JSON, diffs in .textarea, not .input</item>
</ux>

<typography>
  <font>Styrene A</font>
  <page-title>.page-title — 24px weight 700 (not 32–40px hero)</page-title>
  <page-desc>.page-desc — 15px secondary, one line when possible</page-desc>
  <panel-title>.card-title — 17px weight 700</panel-title>
  <body>15px weight 400</body>
  <label>.field__label — 13px weight 500 secondary</label>
  <mono>.textarea — 13px ui-monospace for logs/code</mono>
</typography>

<spacing>
  <page-sections>32px between major blocks — .stack--l</page-sections>
  <panels>20px between gray cards — .stack</panels>
  <inside-panel>16px label→field, 16px field→toolbar</inside-panel>
  <title-to-desc>12px — var(--alfa-gap-s)</title-to-desc>
  <main-head-to-content>.main__top → content: 28px (.main__top margin-bottom) — шапка не прилипает к блокам</main-head-to-content>
  <dash-metrics-row>.dash-metrics margin-top 16px · margin-bottom 28px — 4 metric-карточки ниже заголовка, с воздухом до следующего блока</dash-metrics-row>
  <dash-card-inset>
    .dash-card — padding var(--dash-card-padding) = 20px со всех сторон; контент не ближе 20px к краю серой плашки
    .dash-card__head → body/chart/hbars — gap var(--dash-card-head-gap) = 18px
    Внутри .dash-card: графики, .dash-hbars, .dash-breakdown — width 100%, min-width 0, без negative margin и без выхода за padding
    Track/bar/legend — только внутри content box карточки, не под padding и не за скруглением
  </dash-card-inset>
</spacing>

<radius>
  <panel>28px — .card (keep Alfa rounded panels)</panel>
  <control>12px — .input, .textarea, .btn</control>
  <nav-item>99px pill — .sidenav__link (product sidenav)</nav-item>
  <nav-item-legacy>12px — .sidebar__link (flat shell only)</nav-item-legacy>
  <pill>99px — .badge, .btn--black</pill>
</radius>

<components>
  <app-shell>.shell — sidenav + main on gray canvas (preferred)</app-shell>
  <app-shell-legacy>.app-shell — flat sidebar + main (legacy)</app-shell-legacy>
  <sidenav>.sidenav + .sidenav__label + .sidenav__link + .sidenav__badge</sidenav>
  <sidebar-legacy>.sidebar + .sidebar__section + .sidebar__link — do not use in new screens</sidebar-legacy>
  <page-head>.page-head with .page-title + .page-desc</page-head>
  <field>.field + .field__label + .textarea | .input</field>
  <toolbar>.toolbar — primary btn + secondary + .hint text</toolbar>
  <stack>.stack (20px gap) / .stack--l (32px) — vertical panel lists</stack>
  <step-list>.step-list — numbered action items for runbooks</step-list>
  <results>.results-stack — output panels, hidden until data ready</results>
  <table>.table — history/logs, sticky-friendly dense rows</table>
</components>

<badge usage="internal">
  <allowed>.sidenav__badge (count) · .health / .health--ok|warn|bad в таблицах · .dot-row в stat-карточках · notify dot на bell</allowed>
  <forbidden-top>.status-row и любые .badge-ряды сразу под .main__top (At risk, prod, service tag…) — не добавлять</forbidden-top>
  <warn>severity / pending / at-risk в таблице — .health--warn или .health, не .badge--warn pill row</warn>
  <tag>service or team (.badge--tag) — только внутри строк таблицы/карточки, не под заголовком страницы</tag>
  <neutral>env, region, meta (.badge--neutral) — same rule</neutral>
  <ok>success / healthy — .health--ok или .badge--ok в контексте строки, не декоративный ряд сверху</ok>
</badge>

<button>
  <primary>.btn--primary — single main action per screen</primary>
  <secondary>.btn--secondary — white + border, secondary actions on gray .card</secondary>
  <black-pill>.btn--black — filters/chips only, not page actions</black-pill>
  <size>.btn--s (44px) in toolbars next to fields; default .btn for standalone CTAs</size>
</button>

<patterns>
  <analyze-screen>
    .main__top (28px gap) → .dash-metrics или .page-desc → .card (input + .toolbar) → .results-stack
  </analyze-screen>
  <list-screen>
    .board + .data-table — dense rows, hover, columns aligned (Linear Initiatives logic)
  </list-screen>
  <timeline-screen>
    .timeline-wrap + .timeline — month header, week grid, .timeline__bar + milestone diamonds
  </timeline-screen>
  <navigation>
    .sidenav with grouped .sidenav__label sections · .view-tabs pills · .view-panel switcher
  </navigation>
  <dash-screen>layout + chart colors — см. styles.css блок «Dash» · dash.js</dash-screen>
  <dash-breakdown>.dash-breakdown__row — grid 3 col: name · value · delta (отдельные элементы, не inline)</dash-breakdown>
  <dash-hbar>.dash-hbar__top + .dash-hbar__track — fill только внутри track</dash-hbar>
  <health-status>
    .health--ok | .health--warn | .health--bad — On track / At risk / Off track
  </health-status>
  <empty-state>
    .card centered text: what to do + one .btn--primary — no illustration placeholders
  </empty-state>
</patterns>

<icons required="true">
  <archive>ui/icons.zip → ui/icons/ · ui/photos.zip → ui/photos/</archive>
  <setup>см. &lt;assets-setup&gt; — unzip после clone</setup>
  <usage>&lt;img class="ui-icon" src="ui/icons/History- 192x192.png" width="20" alt=""&gt;</usage>
  <class>.ui-icon 20px · .ui-icon--m 24px · .ui-icon--l 32px</class>
  <on-dark>On .banner-dark or any bg #0b1f35 — add .ui-icon--on-dark (recolor icon white)</on-dark>
  <on-primary>On .btn--primary or any bg #ef3124 — add .ui-icon--on-primary (recolor icon white)</on-primary>
  <required>Always add .ui-icon where it helps scan: sidebar nav, toolbar buttons, filters, empty states — never leave icon slots empty</required>
  <semantic>Pick icon by meaning (History → logs, Funnel → filter, Enter → run). No exact match → neutral: Component, Apps, Information Circle</semantic>
  <neutral-fallback>Component · Apps · Information Circle · Menu Burger Horizontal</neutral-fallback>
  <prefer>History, Funnel, Check Circle, Attention Circle, Menu Burger, Enter, Exit, Component</prefer>
  <skip>emoji names (Angry, Happy, Kiss…)</skip>
</icons>

<linear-adapted>
  Take from Linear: sidebar sections, view tabs, tree table, health pills, dot stats, activity chevrons, roadmap gantt.
  Keep Alfa: white page, gray .board/.card, Styrene, red primary, no dark theme.
</linear-adapted>

<fonts setup="required">
  <path>fonts/StyreneA-Regular.woff2</path>
  <path>fonts/StyreneA-Medium.woff2</path>
  <path>fonts/StyreneA-Bold.woff2</path>
</fonts>

<usage>
  <html>&lt;link rel="stylesheet" href="ui/styles.css" /&gt;</html>
  <shell>&lt;div class="shell"&gt;&lt;aside class="sidenav"&gt;…&lt;/aside&gt;&lt;main class="main"&gt;…&lt;/main&gt;&lt;/div&gt;</shell>
  <example-link>&lt;a class="sidenav__link sidenav__link--active" href="#"&gt;&lt;img class="ui-icon" src="ui/icons/History- 192x192.png" alt="" /&gt;&lt;span class="sidenav__link-text"&gt;Запросы&lt;/span&gt;&lt;/a&gt;</example-link>
</usage>

<forbidden>
  <item>Landing layout — centered hero, huge h1 (36px+), marketing CTA rows without sidebar</item>
  <item>.banner-dark as main page layout — dark sections for internal tools only if full-width alert</item>
  <item>Offer-card grids (.card--action rows) — marketing pattern, not internal</item>
  <item>Multiple red buttons on one screen</item>
  <item>Gray .btn on gray .card — invisible actions</item>
  <item>.card:hover on static panels — panels must not feel like links</item>
  <item>Emoji or .icon-chip letter placeholders when ui/icons/ PNG exists for that action</item>
  <item>Guest or profile photos other than ui/photos/ — no initials, no /tmp paths</item>
  <item>Sidebar nav item, filter chip, or primary toolbar button without .ui-icon when a semantic or neutral icon fits</item>
  <item>3D landing PNG (D_*.png) or rocky SVG — use ui/icons/*.png instead</item>
  <item>Colored .ui-icon on dark bg (#0b1f35, .banner-dark) without .ui-icon--on-dark</item>
  <item>Colored .ui-icon on red bg (#ef3124, .btn--primary) without .ui-icon--on-primary</item>
  <item>Travel / B2C copy patterns unless explicitly B2C task</item>
  <item>Full-width colored backgrounds on body — white page always</item>
  <item>Light-red badge on gray panel — use .badge--tag or .badge--warn</item>
  <item>Flat .sidebar without .shell for new product screens — use .sidenav</item>
  <item>Dark promo / upgrade cards at bottom of .sidenav</item>
  <item>Sidenav link transition or sliding active indicator — instant switch only</item>
  <item>box-shadow on any element — cards, buttons, panels, focus rings</item>
  <item>Orange #de6a00, .icon-chip--orange, or any orange accent</item>
  <item>Dash bar charts as %-height divs without Y-axis baseline — use SVG + rules in styles.css «Dash»</item>
  <item>SVG chart text (&lt;text&gt;) with preserveAspectRatio="none" — сплющивает подписи; оси только HTML (.dash-chart__ylabels / __xlabels)</item>
  <item>Inline delta/badge inside .dash-breakdown__val — ломает выравнивание; delta = отдельная 3-я колонка grid</item>
  <item>.dash-hbar__fill шире .dash-hbar__track — overflow:hidden на track, max-width:100% на fill, width clamp 0–100%</item>
  <item>Horizontal bar fill в одной grid-строке с label+value — track всегда на отдельной строке (.dash-hbar__top + __track)</item>
  <item>Контент .dash-card ближе 20px к краю плашки — padding только на .dash-card, дочерние блоки без negative margin</item>
  <item>График или bar chart шире content box карточки — width:100%, min-width:0, overflow не выходит за --dash-card-padding</item>
  <item>.status-row or decorative .badge pills under .main__top (At risk, prod, llm-proxy, streaming ok…) — use .health in table rows instead</item>
  <item>Tight spacing under .main__top — keep margin-bottom 28px; .dash-metrics margin-top 16px</item>
</forbidden>

</ui>
