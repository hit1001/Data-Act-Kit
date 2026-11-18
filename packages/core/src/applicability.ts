// Which Data Act Chapter II obligations apply to a product model (Art. 7(1), Art. 50).
import type { EnterpriseSize } from './types.ts';

export const CHAPTER_II_APPLIES_FROM = new Date('2025-09-12T00:00:00Z');
/** Art. 3(1) applies to connected products placed on the market after this date (Art. 50). */
export const ART_3_1_PLACED_AFTER = new Date('2026-09-12T00:00:00Z');

export interface MakerProfile {
  readonly size: EnterpriseSize;
  /** Has a partner or linked enterprise that is not micro/small (Art. 7(1), Annex Art. 3 of 2003/361/EC). */
  readonly hasNonSmallPartnerOrLinked: boolean;
  /** Subcontracted to manufacture or design the product or provide the related service (Art. 7(1)). */
  readonly subcontracted: boolean;
  /** Date the enterprise first qualified as medium-sized; required when size is 'medium'. */
  readonly mediumSince: Date | null;
}

export interface Applicability {
  readonly chapterII: boolean;
  readonly art3_1ByDesign: boolean;
  readonly reason: string;
  /** When the next change in applicability happens, if one is scheduled. */
  readonly changesAt: Date | null;
}

const addYear = (d: Date): Date => { const x = new Date(d); x.setUTCFullYear(x.getUTCFullYear() + 1); return x; };

export function applicability(maker: MakerProfile, placedOnMarketAt: Date, now: Date): Applicability {
  if (now < CHAPTER_II_APPLIES_FROM) {
    return { chapterII: false, art3_1ByDesign: false, reason: 'Chapter II applies from 12 Sep 2025', changesAt: CHAPTER_II_APPLIES_FROM };
  }
  const smallExempt = (maker.size === 'micro' || maker.size === 'small') &&
    !maker.hasNonSmallPartnerOrLinked && !maker.subcontracted;
  if (smallExempt) {
    return { chapterII: false, art3_1ByDesign: false, reason: 'Micro or small enterprise exempt (Art. 7(1))', changesAt: null };
  }
  if (maker.size === 'medium') {
    if (!maker.mediumSince) throw new Error('mediumSince is required for a medium-sized enterprise');
    const enterpriseGraceEnds = addYear(maker.mediumSince);
    const productGraceEnds = addYear(placedOnMarketAt);
    const graceEnds = enterpriseGraceEnds > productGraceEnds ? enterpriseGraceEnds : productGraceEnds;
    if (now < graceEnds) {
      return {
        chapterII: false, art3_1ByDesign: false,
        reason: now < enterpriseGraceEnds
          ? 'Medium-sized enterprise for less than one year (Art. 7(1))'
          : 'Product placed on the market by a medium-sized enterprise less than one year ago (Art. 7(1))',
        changesAt: graceEnds,
      };
    }
  }
  const byDesign = placedOnMarketAt > ART_3_1_PLACED_AFTER;
  return {
    chapterII: true,
    art3_1ByDesign: byDesign,
    reason: byDesign ? 'Chapter II applies; access by design required (Art. 3(1), Art. 50)'
      : 'Chapter II applies; product placed on the market on or before 12 Sep 2026, so Art. 3(1) does not apply',
    changesAt: null,
  };
}
