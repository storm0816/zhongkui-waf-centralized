# AGENTS.md

# Project Frontend Design Rules

This project is an enterprise administration platform.

All frontend changes must prioritize:

- clarity
- consistency
- usability
- information density
- maintainability
- accessibility
- responsive behavior
- operational efficiency

The UI should feel like a mature enterprise SaaS product.

Preferred visual references:

- Cloudflare Dashboard
- GitHub
- Linear
- Stripe Dashboard
- Vercel Dashboard

Use these products only as quality references.

Do not directly copy their branding, colors, layouts, or proprietary visual identity.

---

# 1. Core Rule

Before modifying any frontend code:

1. Inspect the existing project structure.
2. Inspect existing reusable components.
3. Inspect existing CSS variables and design tokens.
4. Inspect the current UI framework and dependencies.
5. Reuse existing components whenever practical.
6. Preserve existing business logic.
7. Avoid unnecessary dependency changes.

Do not rewrite working frontend architecture simply to make the UI look newer.

When asked to optimize UI, improve the existing system incrementally.

---

# 2. Design Direction

The visual style should be:

- modern
- professional
- restrained
- clean
- compact
- data-oriented
- enterprise-focused

Avoid interfaces that look obviously AI-generated.

Specifically avoid excessive:

- gradients
- glassmorphism
- huge titles
- oversized hero sections
- giant empty spaces
- colorful decorative icons
- excessive card layouts
- excessive shadows
- excessive border radius
- decorative animations
- random colors

Do not turn an enterprise dashboard into a marketing website.

---

# 3. UI Technology

Prefer the project's existing frontend stack.

If the project already uses a component library, reuse it.

For new React-based projects or new components where no design system exists,
prefer mature and maintainable solutions such as:

- Tailwind CSS
- shadcn/ui
- Radix UI primitives
- Lucide React
- TanStack Table
- React Hook Form
- Zod

Do not introduce a new UI framework without a strong technical reason.

Do not replace the project's current UI framework unless explicitly requested.

Before implementing a custom component, check whether an equivalent reusable
component already exists.

---

# 4. Application Layout

For administration systems, prefer a conventional enterprise layout:

- left sidebar
- top navigation/header
- main content area
- breadcrumb when useful
- contextual toolbar
- content sections
- data tables

The layout should make efficient use of desktop screen space.

Do not center narrow content unnecessarily.

Administration interfaces should generally use more horizontal space than
marketing websites.

Typical layout:

Sidebar
→ Header
→ Breadcrumb
→ Page title / actions
→ Filters
→ Main data area
→ Pagination / secondary information

---

# 5. Sidebar

Sidebar navigation should be:

- stable
- predictable
- compact
- easy to scan

Use clear navigation grouping.

Prefer:

- icon + text
- section grouping
- active state
- optional collapsible groups

Avoid:

- large decorative icons
- excessive nesting
- colorful navigation backgrounds
- unnecessary animations

Sidebar width should remain compact.

Collapsed mode may show icons with tooltips.

---

# 6. Header

The top header should only contain useful global actions such as:

- global search
- environment indicator
- notifications
- documentation
- user menu
- theme toggle

Avoid filling the header with decorative content.

---

# 7. Page Header

Each major page should have a clear hierarchy.

Recommended structure:

Page Title
Short optional description
Primary action
Secondary actions

Avoid oversized titles.

Recommended title sizes:

- page title: text-2xl
- major section title: text-lg or text-xl
- normal content: text-sm or text-base
- metadata: text-xs or text-sm

---

# 8. Spacing

Use a consistent spacing scale.

Prefer:

- gap-2
- gap-3
- gap-4
- gap-6
- p-3
- p-4
- p-6

Avoid arbitrary spacing such as:

- mt-[13px]
- px-[19px]

unless required for compatibility.

Enterprise interfaces should be moderately compact.

Do not add excessive padding to:

- tables
- filters
- forms
- navigation
- cards

---

# 9. Border Radius

Prefer restrained border radius.

Recommended:

- rounded-md
- rounded-lg

Use rounded-xl only where appropriate.

Avoid excessive:

- rounded-2xl
- rounded-3xl
- fully rounded large containers

unless the existing design system already uses them.

---

# 10. Shadows and Borders

Prefer subtle borders over heavy shadows.

Use shadows mainly for:

- dropdowns
- popovers
- dialogs
- floating panels

Avoid heavy shadows on every card.

Standard content containers should usually use:

- subtle border
- background separation
- spacing

rather than dramatic shadows.

---

# 11. Cards

Cards should represent meaningful information groups.

Do not wrap every piece of content inside a card.

Good card use cases:

- KPI metrics
- alerts
- grouped configuration
- node health
- system status
- summaries

Bad card use cases:

- every table row
- every text block
- every navigation item
- deeply nested cards inside cards

---

# 12. Dashboard

Dashboard pages should prioritize:

1. system status
2. exceptions
3. important KPIs
4. trends
5. operational actions

Do not prioritize decorative visuals.

Recommended order:

System health
→ Critical alerts
→ KPI summary
→ Traffic / attack trends
→ Node status
→ Recent events
→ Operational shortcuts

KPI cards should be compact.

Typical metrics might include:

- requests
- blocked requests
- attack count
- online nodes
- offline nodes
- bandwidth
- QPS
- response time
- error rate

Each KPI should clearly show:

- value
- label
- optional trend
- optional comparison period

Do not add meaningless percentage arrows.

---

# 13. Charts

Charts should answer operational questions.

Prefer clear chart types:

- line chart for trends
- bar chart for comparisons
- area chart for volume trends
- donut chart only for small category distributions

Avoid:

- 3D charts
- decorative gauges
- unnecessary pie charts
- too many chart colors

Use semantic and consistent colors.

Charts should include:

- readable axis
- tooltip
- legend when required
- loading state
- empty state

Do not hide important information behind hover-only interaction.

---

# 14. Tables

Tables are a primary UI pattern for administration systems.

Use tables for structured operational data.

Tables should support appropriate combinations of:

- sorting
- filtering
- pagination
- search
- column visibility
- row selection
- batch operations
- sticky header
- loading state
- empty state
- error state

Do not add features that are not useful to the actual workflow.

Numbers should usually be right-aligned.

Status columns should be compact.

Actions should usually appear on the right side.

Use icon buttons only when their meaning is obvious.

Otherwise use text or icon + text.

---

# 15. Table Density

Default table density should favor readability and information density.

Avoid excessively tall rows.

For desktop administration systems, row height should generally stay compact.

Do not use giant padding such as:

py-5
py-6

for ordinary data tables.

Prefer approximately:

py-2
py-2.5
py-3

depending on the existing design system.

---

# 16. Status Representation

Use consistent semantic status representation.

Examples:

Healthy / Online:
green

Warning:
amber

Error / Offline / Blocked:
red

Informational:
blue

Neutral:
gray

Do not assign random colors to status badges.

Status badges should be small and readable.

Prefer:

- dot + text
- small badge
- icon + text

Avoid large colorful pills.

---

# 17. Forms

Forms should be easy to scan and operate.

Each field must have:

- label
- input/control
- validation
- disabled state
- error state

Use helper text only when useful.

Prefer structured controls over free-form text fields.

Examples:

Boolean:
Switch or Checkbox

Small fixed set:
RadioGroup

Long option list:
Select or Combobox

Date:
DatePicker

Date range:
DateRangePicker

Do not use an input field when the value can be selected safely.

---

# 18. Form Layout

Simple forms:

single column

Administrative configuration forms:

label + control layout or compact two-column layout where appropriate

Avoid excessively wide inputs.

Group related settings into meaningful sections.

Do not create one card for every field.

---

# 19. Validation

Validation messages should:

- appear near the relevant field
- clearly explain the problem
- suggest correction where useful

Do not display raw backend exceptions directly to users.

Translate technical failures into understandable UI messages while preserving
detailed errors for logs.

---

# 20. Buttons

Use clear action hierarchy.

Primary button:

main action on the page

Secondary button:

alternative or less important action

Destructive button:

delete / permanently disable / destructive operation

Avoid multiple competing primary buttons.

Do not make every button bright or visually dominant.

Button labels should describe actions.

Good:

Create Rule
Save Changes
Deploy
Retry
View Logs

Bad:

OK
Confirm
Submit

when a more specific action is possible.

---

# 21. Destructive Actions

Destructive operations must be clearly differentiated.

Examples:

- delete rule
- remove node
- clear logs
- disable protection
- reset configuration

Require confirmation when consequences are meaningful.

Confirmation dialogs must state what will happen.

Example:

Delete rule "SQL Injection Protection"?

This action cannot be undone.

Avoid generic:

Are you sure?

---

# 22. Dialogs

Use dialogs only when the user must focus on a temporary task.

Good use cases:

- confirmation
- short form
- critical action

Avoid placing complex configuration pages inside modals.

For larger workflows, prefer:

- page
- drawer
- side sheet

---

# 23. Drawers / Sheets

Use side sheets for contextual tasks such as:

- node details
- request details
- attack event details
- log inspection
- lightweight editing

The main user context should remain visible.

---

# 24. Logs

Logs should use a data-dense interface.

Prefer:

- monospace font where appropriate
- timestamp column
- severity
- source
- event
- searchable content
- filters

Important values such as:

IP
URI
Rule ID
Node ID
HTTP status
request ID

should be easy to copy.

Provide copy buttons when helpful.

---

# 25. Security Events

Security event pages should prioritize:

- event severity
- attack type
- source IP
- target
- matched rule
- timestamp
- action taken
- request details
- node
- trace/request ID

The interface should help an operator answer:

What happened?
Where?
When?
Why was it blocked?
Which rule triggered?
Does action need to be taken?

---

# 26. Node Management

Node management views should clearly show:

- node name
- node ID
- IP
- role
- status
- version
- rule version
- last heartbeat
- CPU
- memory
- traffic
- sync status

Offline or unhealthy nodes should be visually obvious without making the entire
page red.

---

# 27. Filters

Filters should be easy to use and easy to reset.

Common filters:

- date range
- node
- status
- attack type
- source IP
- URI
- action
- severity

Prefer commonly used filters visible by default.

Less common filters may go inside:

More Filters

Provide:

Reset

when multiple filters are active.

---

# 28. Search

Search inputs should explain what can be searched.

Example placeholder:

Search IP, URI, Rule ID...

Avoid generic:

Search...

when the search domain is not obvious.

---

# 29. Empty States

Every major data view should have a useful empty state.

Differentiate between:

No data exists

and:

No results match your filters

Examples:

No attack events found.

No results match the selected filters. Try clearing some filters.

Do not use large decorative illustrations unless consistent with the project.

---

# 30. Loading States

Avoid sudden layout shifts.

Use:

- skeletons
- table row placeholders
- progress indicators

where appropriate.

Do not use full-screen loading for small local actions.

Button actions should show local loading state.

Example:

Saving...
Deploying...
Refreshing...

---

# 31. Error States

Error states must explain:

- what failed
- whether retry is possible
- what the user can do next

Provide retry actions when appropriate.

Example:

Failed to load node status.

Retry

Avoid displaying stack traces in normal UI.

---

# 32. Notifications

Use toast notifications for short-lived feedback.

Examples:

Rule saved successfully.

Node configuration deployed.

Failed to update blacklist.

Do not use toast messages for information that must remain visible.

Important persistent problems belong in page-level alerts.

---

# 33. Icons

Prefer Lucide icons unless the project already uses another icon system.

Do not mix multiple icon libraries unnecessarily.

Typical icon sizes:

- 14px
- 16px
- 18px
- 20px

Avoid oversized decorative icons.

Do not use emoji as application icons.

---

# 34. Color System

Use design tokens and semantic colors.

Never scatter raw colors throughout the project if CSS variables or theme
tokens exist.

Prefer semantic roles:

- background
- foreground
- muted
- border
- primary
- secondary
- success
- warning
- destructive
- info

Support dark mode if the project provides it.

---

# 35. Dark Mode

Dark mode must preserve:

- contrast
- hierarchy
- readable tables
- chart visibility
- status visibility

Do not implement dark mode by simply changing the page background to black.

Use theme tokens consistently.

---

# 36. Typography

Use one primary sans-serif font unless the project already specifies another.

Use monospace selectively for:

- IP addresses
- hashes
- IDs
- logs
- code
- request values

Maintain clear hierarchy.

Do not use too many font sizes or font weights.

---

# 37. Responsive Behavior

All new UI should work on:

- desktop
- laptop
- tablet
- mobile

However, desktop usability has priority for operational administration pages.

Do not destroy desktop information density just to make the design mobile-first.

For narrow screens:

- collapse sidebar
- stack filters
- move secondary actions into menus
- allow tables to scroll horizontally
- selectively convert simple tables into cards

Do not convert every desktop table into cards.

---

# 38. Accessibility

Use semantic HTML where possible.

Interactive components must support keyboard operation.

Inputs require associated labels.

Icon-only buttons require accessible labels.

Maintain visible focus states.

Maintain sufficient contrast.

Do not rely only on color to communicate status.

---

# 39. Animation

Animations should be subtle and functional.

Good:

- dropdown transition
- drawer transition
- loading feedback
- hover feedback

Avoid:

- bouncing elements
- unnecessary entrance animations
- large page transitions
- decorative motion

Administration interfaces should feel fast and stable.

---

# 40. Performance

Do not sacrifice performance for visual effects.

Avoid unnecessary:

- re-renders
- large dependencies
- animation libraries
- giant icon libraries
- duplicated components

For large tables or logs, consider virtualization when needed.

---

# 41. Existing Business Logic

UI optimization must preserve:

- API behavior
- permissions
- routing
- validation logic
- request parameters
- form semantics
- existing workflows

Do not modify backend APIs merely for visual cleanup unless explicitly asked.

When business logic must change, explain the reason before implementing it.

---

# 42. Refactoring Policy

When improving an existing page:

First identify:

1. visual inconsistencies
2. component duplication
3. spacing problems
4. information hierarchy problems
5. interaction problems
6. missing UI states
7. responsive problems
8. accessibility problems

Then improve incrementally.

Avoid complete rewrites unless the current code structure prevents safe
maintenance.

---

# 43. Dependency Policy

Before installing a package:

1. check whether an existing dependency can solve the problem
2. check whether the browser/platform can solve it natively
3. evaluate maintenance activity
4. evaluate bundle impact

Do not install packages merely to implement trivial UI behavior.

Never replace a stable existing UI framework without explicit permission.

---

# 44. AI-generated UI Prevention

The following visual patterns should be treated as warning signs:

- gradient background everywhere
- giant centered page titles
- excessive rounded-3xl containers
- large colorful metric cards
- decorative sparkles
- random purple/blue gradients
- excessive glass effects
- every section inside a card
- oversized icons
- excessive empty space

If the generated UI resembles a generic AI landing page, redesign it.

Enterprise tooling should prioritize operational clarity.

---

# 45. WAF-Specific UX

For WAF-related screens, prioritize operational workflows.

Important modules may include:

- Dashboard
- Attack Events
- Traffic Analytics
- Security Rules
- Blacklist
- Whitelist
- Rate Limiting
- Node Management
- Cluster Status
- Logs
- System Settings

The design should allow an operator to quickly identify:

- current system health
- active threats
- recent attacks
- blocked requests
- unhealthy nodes
- failed synchronization
- rule deployment status

Critical problems should surface clearly.

Normal healthy states should remain visually calm.

---

# 46. Security Rule Editor

Security rules should clearly expose:

- rule name
- rule ID
- status
- priority
- matching conditions
- action
- scope
- last modified
- version

Editing a rule should make complex conditions readable.

Use structured builders when possible.

Example:

IF

Source IP
is in
[IP List]

AND

URI
contains
/admin

THEN

Block

Avoid forcing users to edit raw JSON unless the feature is specifically for
advanced users.

---

# 47. Blacklist / Whitelist

Lists should support:

- IP
- CIDR
- description
- source
- created time
- expiration
- status

Provide clear distinction between:

manual entry
automatic entry
security-rule generated entry

Batch import/export may be supported if already part of the product workflow.

---

# 48. Cluster and Synchronization

Cluster interfaces should clearly expose:

- master / node role
- online state
- heartbeat
- configuration version
- rule version
- last synchronization
- synchronization result

Version mismatch should be easy to detect.

Do not require operators to manually compare long version strings if a visual
status can communicate the mismatch.

---

# 49. Monitoring UX

Operational monitoring pages should answer:

Is the system healthy?

Is traffic abnormal?

Are attacks increasing?

Are nodes synchronized?

Is anything requiring immediate action?

Prioritize these questions over visual decoration.

---

# 50. Final Review Checklist

Before considering a frontend task complete, verify:

- business behavior preserved
- existing components reused
- no unnecessary dependencies added
- layout hierarchy is clear
- spacing is consistent
- typography is consistent
- colors are semantic
- table density is appropriate
- loading state exists where needed
- empty state exists where needed
- error state exists where needed
- hover/focus/disabled states work
- responsive behavior works
- accessibility basics are satisfied
- destructive actions are protected
- UI does not look generically AI-generated

If the implementation fails any of these checks, improve it before finishing.