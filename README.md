<table border="1">
  <thead>
    <tr>
      <th>Detection Method</th>
      <th>Description</th>
      <th>Pros</th>
      <th>Cons</th>
      <th>Progress</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Unexpected Master Activity</td>
      <td>Monitor all masters. If a master becomes active (e.g., owns bus cycles) when not scheduled or expected, trigger a warning.</td>
      <td>Very generic. Catches many classes of trojans.</td>
      <td>Needs basic knowledge of which master should be active normally.</td>
      <td>❌</td>
    </tr>
    <tr>
      <td>Master+Sensitive Memory Access</td>
      <td>When any master becomes active, watch if it accesses sensitive regions (e.g., 0x2000_0000 to 0x2000_0FFF). Trigger if suspicious reads occur.</td>
      <td>Covers many types of RAM snooping attacks.</td>
      <td>If legit processes also access these areas, you must whitelist them.</td>
      <td>✅</td>
    </tr>
    <tr>
      <td>Arbiter Behavior Monitoring</td>
      <td>Check if a master unexpectedly wins arbitration when it shouldn't (e.g., lower-priority master wins when higher-priority still requests).</td>
      <td>Very strong for bus attacks.</td>
      <td>Requires a slightly smarter Arbiter (with self-reporting of grants).</td>
      <td>❌</td>
    </tr>
    <tr>
      <td>Timing Anomalies</td>
      <td>Watch for unusual bus activity timing: e.g., masters suddenly bursting RAM reads outside of known busy windows (especially at weird times like system idle).</td>
      <td>No need to know addresses. Catches side-channel style trojans too.</td>
      <td>May require profiling normal system behavior.</td>
      <td>❌</td>
    </tr>
    <tr>
      <td>Address Access Profiling</td>
      <td>Learn typical address usage patterns. For example: Master A writes only to addresses X, Y, Z. Deviations → suspicious.</td>
      <td>Extremely strong. No false positives if well trained.</td>
      <td>Requires a learning phase (in training mode).</td>
      <td>❌</td>
    </tr>
    <tr>
      <td>Read/Write Behavior Profiling</td>
      <td>Masters typically write a lot (CPU, AES), but trojans tend to read keys a lot. Profiling read/write ratios per master can help.</td>
      <td>Lightweight additional protection.</td>
      <td>May be fooled by trojans that mimic normal write/read patterns.</td>
      <td>❌</td>
    </tr>
  </tbody>
</table>

