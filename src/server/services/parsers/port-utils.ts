/**
 * port-utils.ts
 *
 * Shared port normalisation utility used by both the main parser
 * and the new sub-parsers (stp.parser.ts, portchannel.parser.ts).
 *
 * Extracted here to avoid circular imports.
 */

export function normalizePort(port: string): string {
  if (!port) return '';
  let p = port.trim();
  p = p.replace(/\s+/g, '');
  p = p.replace(/([a-zA-Z])-([a-zA-Z])/g, '$1$2');

  if (/^hundredgige/i.test(p))           return p.replace(/^hundredgige/i, 'Hu');
  if (/^hundredgigabitethernet/i.test(p)) return p.replace(/^hundredgigabitethernet/i, 'Hu');
  if (/^100ge/i.test(p))                 return p.replace(/^100ge/i, 'Hu');
  if (/^fortygige/i.test(p))             return p.replace(/^fortygige/i, 'Fo');
  if (/^fortygigabitethernet/i.test(p))  return p.replace(/^fortygigabitethernet/i, 'Fo');
  if (/^40ge/i.test(p))                  return p.replace(/^40ge/i, 'Fo');
  if (/^twentyfivegige/i.test(p))        return p.replace(/^twentyfivegige/i, 'Twe');
  if (/^25ge/i.test(p))                  return p.replace(/^25ge/i, 'Twe');
  if (/^tengigabitethernet/i.test(p))    return p.replace(/^tengigabitethernet/i, 'Te');
  if (/^tegigabitethernet/i.test(p))     return p.replace(/^tegigabitethernet/i, 'Te');
  if (/^10gigabitethernet/i.test(p))     return p.replace(/^10gigabitethernet/i, 'Te');
  if (/^xgigabitethernet/i.test(p))      return p.replace(/^xgigabitethernet/i, 'Te');
  if (/^tengige/i.test(p))               return p.replace(/^tengige/i, 'Te');
  if (/^10ge/i.test(p))                  return p.replace(/^10ge/i, 'Te');
  if (/^gigabitethernet/i.test(p))       return p.replace(/^gigabitethernet/i, 'Gi');
  if (/^gigethernet/i.test(p))           return p.replace(/^gigethernet/i, 'Gi');
  if (/^gige/i.test(p))                  return p.replace(/^gige/i, 'Gi');
  if (/^gig(?=[0-9\/])/i.test(p))        return p.replace(/^gig/i, 'Gi');
  if (/^fastethernet/i.test(p))          return p.replace(/^fastethernet/i, 'Fa');
  if (/^fas(?=[0-9\/])/i.test(p))        return p.replace(/^fas/i, 'Fa');
  if (/^ethernet/i.test(p))              return p.replace(/^ethernet/i, 'Eth');
  if (/^port-channel/i.test(p))          return p.replace(/^port-channel/i, 'Po');
  if (/^portchannel/i.test(p))           return p.replace(/^portchannel/i, 'Po');
  if (/^aggregatedethernet/i.test(p))    return p.replace(/^aggregatedethernet/i, 'ae');
  if (/^serial/i.test(p))                return p.replace(/^serial/i, 'Se');
  if (/^management/i.test(p))            return p.replace(/^management/i, 'Mgmt');
  if (/^vlan/i.test(p))                  return p.replace(/^vlan/i, 'Vl');
  if (/^(ge|xe|et|ae)-/i.test(p))        return p;
  return p;
}
