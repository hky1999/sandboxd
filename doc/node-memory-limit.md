# Optional aggregate sandbox memory limit

This opt-in cgroup v2 policy caps the configured sandbox parent (for example `/sandboxd` or `/akernel`) at startup and clips node-resource reporting to the same budget. It is disabled by default. Deployments retain ownership of budgets and of limits on components outside the parent.

```toml
[plugin.resource.memory_limit]
enabled = true
system_reserve = "4GiB"
control_reserve = "auto"
other_reserve = "8GiB"
safety_buffer = "8GiB"
runtime_headroom = "2GiB"
```

These settings extend an existing sandboxd configuration. The public sample uses `/sandboxd`; AKernel deployments can select `/akernel` through `cgroup_root_name`. Reporting additionally requires `[plugin.node_resource]` with `sock_path` and a `cgroup` or `kubernetes` provider. Without that module, the parent hard limit still applies. These are examples, not production defaults. Sizes accept integer bytes or `B`, `KiB`, `MiB`, `GiB`, `TiB`. System, control and safety reserves must be positive. Other reserve and runtime headroom default to zero. Control reserve can be an explicit size or `auto`, which requires a positive finite `memory.max` on the visible `/system.slice`. Distill-fs's positive finite `[plugin.image].cgroup_memory_limit` supplies its budget; it is rounded up to a page. No current-use samples or historical peak database are required.

The calculation is:

```text
T = min(/proc/meminfo MemTotal, finite memory.max values on parent ancestors)
R = system_reserve + control_reserve + distill-fs budget + other_reserve
candidate = round_down_to_page(T - R - safety_buffer)
actual_max = min(candidate, existing finite parent memory.max)
reported_capacity = min(provider_capacity, actual_max - runtime_headroom)
/resource Mem = reported_capacity - active transient reservations
```

The parent's own old limit is excluded when calculating T, so restarts do not subtract budgets repeatedly. At a real hierarchy root there may be no `memory.max`; a Docker cgroup namespace root can expose a finite container limit, which is included. Only visible ancestors can be inspected: container memory limits must represent the delegated node budget if higher host ancestors are hidden. The control daemon's current group is not an ancestor of a sibling `/akernel`.

For example, T=64GiB, system=4GiB, control=6GiB, distill-fs=8GiB, other=4GiB and safety=4GiB give candidate=38GiB. With runtime headroom=2GiB, the reporting ceiling is 36GiB. If an existing parent cap is 32GiB, it is preserved and the reporting ceiling is 30GiB. A Kubernetes provider reporting 28GiB yields 28GiB: its already-reserved capacity is clipped, not reduced by R a second time. Sandbox live usage is not subtracted from this capacity; the scheduler already tracks sandbox allocations and subtracts them from capacity.

## Capacity reporting and upgrades

With `memory_limit.enabled=true`, cgroup-provider memory capacity comes from the managed sandbox parent and its ancestors rather than sandboxd's own service group. With the policy disabled, the provider continues to use sandboxd's own cgroup. CPU discovery is unchanged.

Cgroup and Kubernetes providers preserve byte precision instead of rounding down to whole GiB. This precision change also applies with `memory_limit.enabled=false`. For example, a provider capacity of 10.5GiB that was previously reported as 10GiB is now reported as 10.5GiB, recovering 512MiB previously lost to rounding. Whole-GiB values remain unchanged. Final advertised capacity remains subject to configured ceilings and transient reservations, so the increase may be masked. Operators should account for this change when comparing scheduling capacity and monitoring values across upgrades. YuanRong converts resource units internally; its view may have a small conversion tolerance.

## Startup and rollout

With the policy enabled, sandboxd writes `memory.max` only when adding a finite limit to an unlimited parent or lowering an existing finite limit. Both cases require the entire sandbox subtree to have no processes and residual `memory.current` to be no greater than the new limit. Startup refuses the change before writing if these conditions are not met; rollout runbooks must drain the subtree before either operation.

An existing finite cap that is equal to or lower than the computed candidate can be reused with live sandboxes. A higher candidate, for example after memory hot-add or a reduction in reserves, does not automatically raise the existing stricter cap. Draining and restarting alone does not raise it either; increasing an existing cap requires a separate operator-managed change.

Assuming the remaining configuration is valid, the following cases apply when the sandbox subtree still has processes:

| Existing `memory.max` | New candidate | Startup behavior |
| --- | --- | --- |
| `max` | 38GiB | Refuse startup; drain before adding the finite cap. |
| 38GiB | 36GiB | Refuse startup; drain before lowering the cap. |
| 38GiB | 38GiB | Reuse 38GiB without rewriting the cap. |
| 38GiB | 46GiB | Retain 38GiB without rewriting the cap. |

Startup refuses invalid configuration, exhausted budgets, missing controllers, failed writes and mismatched readback. Headroom must fit under the actual cap. The implementation changes only `memory.max`; `memory.high`, swap policy and group OOM policy retain existing settings. Policy changes are evaluated on a controlled restart.

New nodes with the same image and configuration calculate T at startup; different node sizes therefore receive different caps without a per-node hardcoded limit. Reserves remain deployment policy and must be updated when component budgets change. `other_reserve` includes checkpoint and other components outside the sandbox parent; headroom covers costs inside it. Avoid counting a component in both reserves. Fixed reserves alone do not constrain outside components, so this feature cannot guarantee avoidance of all host OOMs. Continue enforcing their deployment limits and monitoring node memory pressure.
