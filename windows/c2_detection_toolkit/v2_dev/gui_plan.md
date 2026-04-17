### Objective
---

Implement a **Data-Driven Dashboard** architecture using the **MVVM (Model-View-ViewModel)** pattern.

#### 1. The Modern UI Tech Stack
For a high-performance security sensor, we will use:
* **WPF with .NET 8**: The industry standard for high-performance Windows desktop apps. It allows for deep integration with your existing C# ETW logic.
* **LiveCharts2**: An ultra-fast, hardware-accelerated charting library to handle the "NetFlow Observability" and "Threat Telemetry" graphs.
* **ModernWpf / MahApps.Metro**: UI frameworks that provide the dark, card-based aesthetic seen in your reference image.

---

#### 2. Proposed Dashboard Layout
Following the layout of your refactored appeal, the C2Console GUI will be divided into functional "Cards":

| Card Component | Description | Legacy Metric Equivalent |
| :--- | :--- | :--- |
| **Global Health Tiles** | Small top-row cards for quick status. | ETW Sensor: Good, ML Engine: Native FFI.png |
| **Telemetry Analytics** | A large central line chart showing real-time event volume. | Events Processed.png |
| **Active Threats List** | A high-contrast datagrid showing the most recent 20 alerts. | Live Threat Telemetry.png |
| **Defense Overview** | A donut chart showing Mitigations vs. Audit logs. | Defenses Fired / Total Mitigations.png |

---

#### 3. Implementation: Bridging the Engine to the GUI
To keep the UI responsive while processing 10,000+ packets/sec, we will use an **ObservableCollection** with a "throttled" update. Instead of updating the GUI for every packet, the UI thread will "pulse" every 500ms to pull the latest batch from the `EventQueue`.

#### 4. Visual Comparison
* **Current State**: Fixed-width terminal boxes with color-coded text strings.png.
* **Target State**: A dark-mode desktop application with interactive charts, hover-effects for threat details, and a sidebar for "Armed/Audit" mode switching.