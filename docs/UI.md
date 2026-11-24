# DaemonSight UI standards

How DaemonSight's pages are laid out, worded and checked. Each rule is short
and names its source where one exists. Rules marked "Owner" come from the
project owner and need no outside source. A source that could not be read is
marked unverified. Sources are listed at the end, with the date each was read.

## Layout and wording rules

These apply to every page. Owner rules, kept as written.

- **Symmetry all the way down.** A page picks its columns once and keeps them
  to the bottom: every card in a column is the same width, and column edges
  line up from the first card to the last. A page may have one column or a main
  column with a side column (a host's Overview), but a card is never narrowed
  in one place to make room for something beside it. A guide that would sit
  beside one card goes inside it, folded (`details`).
- **Short up front.** A card opens with one sentence at most. Longer text
  (terms, caveats, how something is worked out) goes behind an (i) button in the
  card title that opens a popover, or in a small note at the foot of the page.
  On the Settings page that is a group's `note`, `note_title` and `note_links`
  in `settings.GROUPS`; on data pages it is the source panel (`src_button`,
  `src_panel`).
- **Alerts are for now.** A coloured alert box is for something that just
  happened or needs action now (a save, an error). Standing information never
  goes in one.
- **Long pages are reached through each tab's section menu.** A nav tab whose
  page has two or more sections has a small chevron button that opens a menu of
  them (a native popover, `ds-sec-pop`); the tab name still goes to the page.
  The active page's menu lists the cards on it (`app.js` builds it from the page, so it includes cards only some systems have); other tabs list the sections every system has, per host kind, in `web/sections.py`
  (`SECTIONS`), passed to `base.html` as `page_sections`. Only cards every
  render of the page has are in that registry, and `tests/test_sections.py` (with the
  Unraid and OPNsense checks in their own test files) proves each anchor exists.
  A link to a section of the current page scrolls there and flashes it, and
  shows a card that "Hide empty sections" or the filter has hidden. On a phone
  there are no chevrons: each page with sections has a toggle (see Navigation).
- **Dependent options sit under their control.** An option that only matters
  for one value of another setting (the Shodan key under Source) is indented
  under it (`.ds-subpanel`) and shown only while that value is chosen
  (`data-ds-when="<select id>=<value>"`, read by `app.js`; a checkbox has the
  value `on` while ticked: the Docker reader under "Read images and volumes").
  Without JavaScript it stays visible. It belongs to the same form and the same Save button; any
  other action on it posts that form elsewhere with `formaction`, never a
  nested form.
- **Steps fold.** A finding's "What to do" steps are folded behind their
  label, with a solid arrow after it that turns down when open
  (`howto_block` in `_macros.html`), so a list of findings stays short.
  Printing opens them all, and they fold again afterwards (`app.js`).
- **Field help.** One or two short sentences under the control; the default and
  allowed range go on the line below.
- **Menus.** Toggles and choices come first. Then a line, then things you go to
  or do, as menu items with an icon, full width and a hover background, so they
  never look like labels. The account menu is Theme, Hide empty sections, a
  line, Settings, Log out.
- **Navigation.** The header's sections are tabs. "Add a system" is a +, and a
  vertical line separates hub-wide items from the host's own sections.
  The Hosts tab's menu is the hosts themselves (A to Z, each with a status dot,
  the current host marked), a line, then "Recent hub changes". It is never
  rebuilt from the page.
- **Secrets.** Never shown back. A badge says whether one is saved ("A key is
  saved").


## Navigation

- **Desktop: tabs, each with a section menu.** The header shows one tab per
  page. A tab whose page has two or more sections has a small chevron that opens
  a menu of them; the tab name still goes to the page. (Owner. The menu is a
  native popover.)
- **Phone: the header is at most two rows.** Row 1 is the logo and the host
  pill (the name truncates, full name in `title`); row 2 is the filter with the
  menu button beside it, 44 px square. Without a filter the button sits at the
  right of row 1.
- **Phone: one vertical list.** Under 768 px the hamburger panel is a single
  list, one row per item, full width: the hub's items (Hosts, Add a system), a
  line, then the host's pages. Wrapped rows of pills read as scattered.
  (Owner. NN/g finds hidden menus hard to discover, so a phone shows the whole
  list as soon as the menu opens [S7].)
- **Sections fold with the disclosure pattern, not the menu role.** A page with
  sections has its name as a link and, at the right of the row, a separate
  toggle: a `button` with `aria-expanded` and `aria-controls`, controlling a
  list that is `hidden` while closed. The APG disclosure pattern puts
  `role="button"` on the control, `aria-expanded` true when the content is
  visible and false when it is hidden, and optionally `aria-controls` [S1]. Its
  navigation example does not use the `menu` role, because "typical site
  navigation does not need all the keyboard interactions" that role brings
  [S2].
- **Why disclosure and not accordion.** The APG accordion is a stack of headings
  that reveal panels of content, "commonly used to reduce the need to scroll"
  [S3]. Navigation is a list of links with an optional sub-list, which is the
  disclosure pattern's shape; the section toggle is a disclosure inside a nav.
  (The choice is this project's reading of S1 to S3.)
- **The page name and the toggle are two controls.** The link goes to the
  page; the toggle only opens and closes. Do not make one control do both.
  (Owner. The APG navigation example has the same split: links navigate,
  buttons toggle [S2].)
- **Open by default.** The current page's sections start open and the others
  closed. More than one may be open at once. (Owner; NN/g: "let people open
  multiple sections at once" [S4].)
- **The arrow shows the state.** Right when closed, down when open, the same
  solid arrow as the folded "What to do" steps. The APG disclosure button
  "usually" has a triangle pointing right when hidden and down when visible
  [S1].
- **Mark the current page.** The current page's link has `aria-current="page"`,
  and only one link has it [S2].
- **A jump closes the menu.** A section link scrolls to the card and flashes
  it, and on a phone closes the hamburger panel. (Owner.)
- **Without JavaScript every list shows,** as plain nested lists, and there are
  no toggles. (Owner.)
- **The lists line up.** Page names share one left edge; section names share
  another, indented under them with a rule down the left. (Owner: symmetry.)
- **Only phone-specific markup is phone-only.** Desktop must not change when the
  phone menu does; check both (see "Checking a change").

## Disclosure and accordions

- **Fold supporting detail, not what every reader needs.** A finding's "What
  to do" steps fold because the list of findings is what people scan; the steps
  are for the one they open. GOV.UK: "Do not use an accordion for content that
  all users need to see" [S5]. NN/g: avoid accordions when "users need access to
  most content" [S6].
- **Fold when it shortens a page people scan.** On small screens "people often
  stop scrolling before reaching the end of an extremely long page", and
  collapsed headings give an overview [S4]. On a desktop, scrolling is easier
  than choosing what to open [S4], so do not fold what fits.
- **Do not fold content that cannot be chunked, is complex or has several
  levels,** or where an unbroken reading flow matters [S6]. GOV.UK: do not put
  accordions inside accordions [S5].
- **Never hide accepted items.** Accepted and expected items stay visible with
  an inline label; a filter replaces a separate or folded section. (Owner.)
- **A fold has a real control.** Use `details` and `summary` for a plain fold
  (the "What to do" steps) and a `button` with `aria-expanded` when script
  drives it. Printing opens every fold. (Owner; APG [S1].)
- **Test it with someone before adding another.** GOV.UK: use an accordion
  only if there is evidence it helps, because "not all users will notice them
  or understand how they work" [S5].

## Touch targets and focus

- **Rows and buttons that a finger taps are at least 44 by 44 CSS px on a
  phone.** WCAG 2.5.5 (AAA) sets 44 by 44 [S9]; Apple's table gives 44 by 44 pt
  as the default control size on iOS and iPadOS [S10]. DaemonSight takes the
  AAA and Apple figure. Google's Android guidance says 48 dp with 8 dp between
  targets [S11]; use that where there is room.
- **The floor is 24 by 24 CSS px.** WCAG 2.5.8 (AA) allows smaller targets only
  with spacing, an equivalent control, inline text, an unmodified browser
  control, or an essential presentation [S8]. Apple's stated minimum is 28 by 28
  pt [S10]. Never go below 24.
- **Space targets apart.** Apple: spacing "as important as size", about 12 pt
  around controls with a bezel and 24 pt around ones without [S10].
- **Every control shows keyboard focus.** WCAG 2.4.7 (AA): any keyboard
  operable interface has a mode where the focus indicator is visible [S12]. Use
  `:focus-visible` with a 2 px outline in the primary colour and a 2 px offset,
  as the existing controls do. Never `outline: none` without a replacement.
- **Hover styles apply only where hover exists** (`@media (hover: hover)`), so
  a tapped row does not keep a hover background. (Project practice.)
- **Coarse pointers get the larger size.** Controls that are small with a mouse
  (the "What to do" label) grow under `@media (pointer: coarse)`. (Project
  practice.)

## Colour meaning

- **Red is for findings.** Red text, badges and cells mean something needs
  attention: an Unexpected or Changed item, or an error. Nothing decorative is
  red. (Owner.)
- **Yellow is for internet-facing facts.** The "internet-facing" badge and the
  "Yes" in an Internet-facing cell are yellow, so a reader can see what the
  internet can reach, apart from what is wrong. (Owner.)
- **Green is for trusted or healthy.** (Project practice.)
- **Status labels are words, not colour alone.** Every item carries Unexpected,
  Accepted, Changed or Expected as text. WCAG 1.4.1 (A): colour is not the only
  visual means of conveying information [S13]. Only Unexpected and Changed count
  as needing attention (see "Status labels" in DESIGN.md).
- **Alerts are for now.** A coloured alert box is for something that just
  happened or needs action now. (Owner; stated above.)

## Tables on phones

- **Under 768 px a table row becomes a stacked card,** one line per cell with
  the column name as a small label (`data-label`) before the value. The header
  row stays in the page for screen readers (visually hidden). (Project
  practice.)
- **Every cell has a `data-label`,** except a cell that spans the row.
- **Long values wrap** (`overflow-wrap: anywhere`) so a row never scrolls
  sideways. (Project practice.)

## Forms

- **Every field has a visible label or instruction.** WCAG 3.3.2 (A): "Labels
  or instructions are provided when content requires user input" [S14].
- **Field help.** One or two short sentences under the control; the default and
  allowed range go on the line below. (Owner.)
- **GUI-first settings.** Every setting a user can change is on the Settings
  page, and a header control belongs in the one account menu. A config-file
  option with no control there is only for what a user should not change.
  (Owner.)
- **One form, one Save.** Dependent options share the form and the Save button
  of what they depend on. (Owner; see "Dependent options" above.)
- **Secrets are never shown back.** A badge says one is saved. (Owner.)
- **Phone forms are one column.** Settings rows stack under 768 px. (Project
  practice.)

## Motion and print

- **Motion is short and optional.** Arrows turn in about 0.15 s, and a flash
  marks a jump target once. Both turn off under `prefers-reduced-motion:
  reduce`. WCAG 2.3.3 (AAA) says motion triggered by interaction can be
  disabled [S15]. (Project practice.)
- **Print is a report.** The print stylesheet hides the menu, buttons and
  forms, and opens every fold; folds close again afterwards. (Owner.)

## Checking a change

- **Look at it in a browser at 1400 px and at 390 px** before it ships, with
  touch emulation for 390 px. Open the phone menu, open a second page's
  sections, jump to a section, and check a collector host and an OPNsense host.
  (Owner.)
- **Look at every screenshot** and fix what is off. A passing test does not show
  a crooked left edge.
- **Run the tests** (`pytest -q`). `tests/test_sections.py` proves every
  registry anchor exists and that the phone list has one toggle per page, with
  ids that match.

## Sources

Read for this document on 2026-11-19 unless marked.

- S1. WAI-ARIA Authoring Practices Guide, Disclosure (Show/Hide) Pattern.
  https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/ (Description, Keyboard
  Interaction, WAI-ARIA Roles, States, and Properties)
- S2. APG, Example Disclosure Navigation Menu.
  https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/examples/disclosure-navigation/
  (About this example; Accessibility Features)
- S3. APG, Accordion Pattern. https://www.w3.org/WAI/ARIA/apg/patterns/accordion/
  (About This Pattern; WAI-ARIA Roles, States, and Properties). The page gives
  no guidance on when not to use one.
- S4. Nielsen Norman Group, "Accordions Are Not Always the Answer for Complex
  Content on Desktops". https://www.nngroup.com/articles/accordions-complex-content/
  (covers desktop and mobile; read through a summarising fetch, so quotes are
  as returned)
- S5. GOV.UK Design System, Accordion.
  https://design-system.service.gov.uk/components/accordion/ (When to use this
  component; When not to use this component)
- S6. Nielsen Norman Group video, "Accordions: 5 Scenarios to Avoid Them".
  https://www.nngroup.com/videos/avoid-accordions/
- S7. Nielsen Norman Group, mobile navigation patterns (hamburger menus).
  https://www.nngroup.com/articles/mobile-navigation-patterns/ ("out of sight
  is out of mind"; a hamburger fits content-heavy sites, a visible bar fits five
  or fewer options)
- S8. WCAG 2.2, Understanding 2.5.8 Target Size (Minimum), Level AA.
  https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html
- S9. WCAG 2.2, Understanding 2.5.5 Target Size (Enhanced), Level AAA.
  https://www.w3.org/WAI/WCAG22/Understanding/target-size-enhanced.html
- S10. Apple Human Interface Guidelines, Accessibility (Controls: default
  44x44 pt and minimum 28x28 pt on iOS and iPadOS; spacing text). Read from
  Apple's published data file
  https://developer.apple.com/tutorials/data/design/human-interface-guidelines/accessibility.json
  because the page itself needs script.
- S11. Google Accessibility Help, Touch target size.
  https://support.google.com/accessibility/android/answer/7101858 (48dp; 8dp
  spacing)
- S12. WCAG 2.2, Understanding 2.4.7 Focus Visible, Level AA.
  https://www.w3.org/WAI/WCAG22/Understanding/focus-visible.html
- S13. WCAG 2.2, Understanding 1.4.1 Use of Color, Level A.
  https://www.w3.org/WAI/WCAG22/Understanding/use-of-color.html
- S14. WCAG 2.2, Understanding 3.3.2 Labels or Instructions, Level A.
  https://www.w3.org/WAI/WCAG22/Understanding/labels-or-instructions.html
- S15. WCAG 2.2, Understanding 2.3.3 Animation from Interactions, Level AAA.
  https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions.html

Unverified:

- Material Design 3's own 48 dp touch target page could not be read (the site
  returns no text to a fetch). The 48 dp figure is from Google's Android
  accessibility help (S11); Material's density page is cited by search
  summaries only.
- NN/g's article specific to accordions on mobile returned 404 at the address
  tried; S4 covers mobile and desktop in one article.
- NN/g's mobile-navigation page was read through a summarising fetch, not
  verbatim, so its quotes are as returned.
- Which rules above are Owner or project practice is recorded in the text; none
  of those has an outside source.
