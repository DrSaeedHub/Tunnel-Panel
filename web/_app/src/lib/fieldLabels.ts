import type { TFunction } from 'i18next'

/**
 * The tunnel fields the backend names by their wire spelling -- in a diff, in
 * a reconcile report, in a validation error -- and the label the form shows
 * for each. Keyed by the JSON field, valued by the key under `tunnel.fields`.
 */
const TUNNEL_FIELDS: Record<string, string> = {
  tunnel_type_id: 'type',
  tunnel_type: 'type',
  tunnel_side_id: 'side',
  persistence_type_id: 'persistence',
  interface_name: 'interfaceName',
  display_name: 'displayName',
  tunnel_number: 'tunnelNumber',
  local_endpoint: 'localEndpoint',
  remote_endpoint: 'remoteEndpoint',
  bind_device: 'bindDevice',
  ttl: 'ttl',
  tos: 'tos',
  mtu: 'mtu',
  ikey: 'ikey',
  okey: 'okey',
  has_input_checksum: 'inputChecksum',
  has_output_checksum: 'outputChecksum',
  has_input_sequence: 'inputSequence',
  has_output_sequence: 'outputSequence',
  is_path_mtu_discovery: 'pmtudisc',
  is_ignore_df: 'ignoreDf',
  fwmark: 'fwmark',
  tx_queue_length: 'txQueueLength',
  hop_limit: 'hopLimit',
  encap_limit: 'encapLimit',
  address_pool_id: 'addressPool',
  addresses: 'addresses',
  is_enabled: 'enabled',
  note: 'note',
  monitor_target: 'monitorTarget',
  monitor_window_size: 'monitorWindowSize',
  monitor_state_change_samples: 'monitorStateChangeSamples',
}

/** The parts of one address, as `addresses.N.<part>` names them. */
const ADDRESS_PARTS: Record<string, string> = {
  address: 'address',
  prefix_length: 'prefixLength',
  peer_address: 'peerAddress',
}

/**
 * The label for a tunnel field the backend named, in the operator's language.
 *
 * A field this table does not know is returned as the backend spelled it:
 * a raw name is legible to somebody matching it against the API, where a blank
 * would hide which field was meant.
 */
export function tunnelFieldLabel(field: string, t: TFunction): string {
  const key = TUNNEL_FIELDS[field]
  if (key) return t(`tunnel.fields.${key}`)

  // The monitoring overrides are labelled on the form by what they measure,
  // which is the same wording used here.
  switch (field) {
    case 'monitor_interval_seconds':
      return t('diagnostics.ping.interval')
    case 'monitor_timeout_seconds':
      return t('diagnostics.ping.timeout')
    case 'monitor_packet_size':
      return t('diagnostics.ping.packetSize')
    case 'monitor_degraded_loss_percent':
      return t('monitor.loss') + ' · ' + t('monitor.state.Degraded')
    case 'monitor_down_loss_percent':
      return t('monitor.loss') + ' · ' + t('monitor.state.Down')
    case 'monitor_degraded_rtt_ms':
      return t('monitor.latency') + ' · ' + t('monitor.state.Degraded')
  }

  // addresses.0.prefix_length: the part's label, and which address it is when
  // there is more than one.
  const address = /^addresses\.(\d+)\.(\w+)$/.exec(field)
  if (address && ADDRESS_PARTS[address[2]]) {
    const label = t(`tunnel.fields.${ADDRESS_PARTS[address[2]]}`)
    const index = Number(address[1])
    return index > 0 ? `${label} ${index + 1}` : label
  }

  return field
}
