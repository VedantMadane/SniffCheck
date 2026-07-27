# Clustering

Clustering tries to answer one question: can any of these WiFi and BLE results be the same device? 

It doesnt rewrite scan results. It just adds a layer on top that says "these two might be the same <insert thing here>." 

  * Every AP and every BLE result becomes a **node**. 
  * Nodes get scored and compared and a **edge** is added when something might be related                            
  * A and B + evidence + confidence

## Similar is not the same

This is the safety rule and the whole reason this module is careful. Same vendor, nearby MAC, same model, matching name...all useful, none of them prove "same physical device" on their own. *two routers off the same factory line can flag* 

So every bit of evidence gets a class:

```c
PDC_CLASS_PHYSICAL_STRONG  
PDC_CLASS_PHYSICAL_CANDIDATE  
PDC_CLASS_RELATIONSHIP        
PDC_CLASS_PRODUCT_FAMILY      
PDC_CLASS_CONTEXT             
```

Strong stands flags cluster. Candidates need confirmation. Everything else is cosmetic

## Wi-Fi to Wi-Fi

Things we are looking at right now for confidence:

- **NIC bytes** MAC bytes 2,3,4 match and the last byte is close (within 16) stronger than "same vendor"  
     *catches a router broadcasting main + guest + IoT on near-identical MACs*
- **RF**  same radio should be same channel and similar signal
- **SSID** `MyNet`, `MyNet-5G`, `MyNet_Guest` all count. But it ignores `xfinitywifi`, `attwifi`, `eduroam` and friends  a thousand strangers share those, not the same router
- **CDP/LLDP** two APs with the same specific device id = strong. Generic `ap`, `router`, `localhost` dont flag.

## Wi-Fi to BLE

This is a tricky one.....well they're all tricky haha.. Same public OUI + a near MAC suffix = relationship candidate but will **not** flag as a cluster candidate. So just cosmetic ftb.

```c
add_edge(PDC_NODE_WIFI, i, PDC_NODE_BLE, j,
         PDC_EV_MAC_ADJACENT, conf, false);  
```

*being honest down the road when theres a GPS tag we can get a little more confidence so all of this is mainly cosmetic*   

## Promoting a cluster candidate
> first off it sounds cool to word it that way "promoting a cluster candidate"

A "candidate"(node) gets promoted to a cluster only if it has **all three edges**: NIC bytes, SSID, and RF confidence. Must be all 3. Something as simple as a country code mismath will block a node promotion.

## Building the clusters

Collect every edge, then run union-find. Only edges flagged `can_union` actually merge anything. Any group of 2 or more becomes a cluster.

- one device = no cluster
- two or more + promotion evidence = cluster

**RIght now candidate nodes that have not been promoted still show up in the cluster tab. We haven't set up how we want to display that in the UI but it will be sorted out sometime soon-ish. Kinda a medium priority atm.** 

## Cars

A Wi-Fi hotspot and a BLE device that look like the same car maker get grouped as a `vehicle` cluster. This is display only, never a physical claim. *two Fords in traffic might share a make(if it decodes), but that doesn't mean its the same car..truck..thing..A ui decision hasn't really been made on these cases yet..*

## Exporting cluster

Clusters export as `device_cluster` records: kind (`physical` or `vehicle`), confidence, members, and the edges with their confidence decision:

- `physical` = used as same device proof  *still working this out because this can false flag* 
- `candidate` = maybe, not enough to merge
- `product_family` = same kind of thing
- `conflict` = looked similar but no joy *sounded cool in my head*

## Environments (place memory)

Same primitives, one layer up. Instead of "are these two the same device?" a place asks "have I been *here* before?" 

A place isn't a pile of BSSIDs, it's a handful of **landmarks**. A landmark is an infrastructure *unit* — same NIC-byte / capability-fingerprint grouping from the Wi-Fi rules above — so a router that shouts main + guest + IoT + 5GHz collapses to **one** landmark, not five. Raw BSSIDs would just saturate and every place would start looking like every other place.

Matching a scan to a known place is a weighted overlap, and the weighting is the same instinct as the SSID rule: a unit that shows up in *lots* of places (carrier APs, the mesh you carry around) barely counts, a unit that's unique to one place is what actually pins it. Plus a floor — a couple of distinctive landmarks have to line up or it's a new place, not a match. That's what stops home and work from smearing together.

Landmarks earn their keep over repeat visits. A fixture that keeps showing up gets **confirmed**; a phone that walked past once gets pruned. "Learn this place" just does that on purpose over a few scans, and if you reposition between them the brain can tell a bolted-down AP from a person wandering through. Everything's editable — pin, remove, rename, forget — because no heuristic is perfect and you know your own place better than the box does.
