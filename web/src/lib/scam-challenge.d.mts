export interface Rank { roman: string; name: string; lo: number; hi: number; color: string }
export interface LevelStats { correct: number; incorrect: number; avgTime: number; score: number }
export interface Progress {
  version: number;
  highestUnlocked: number;
  completed: number[];
  perfect: number[];
  scores: Record<number, number>;
  bestCorrect: Record<number, number>;
  stats: Record<number, LevelStats>;
  totalScore: number;
}
export interface LevelResult { level: number; score: number; correct: number; incorrect: number; avgTime: number; passed: boolean; isLegend: boolean }
export interface FinishOutcome {
  progress: Progress;
  rankUp: Rank | null;
  blockedByRank: { rank: Rank; missing: number[] } | null;
  result: LevelResult;
}
export const MAX_POINTS: number;
export const QUESTIONS_PER_LEVEL: number;
export const LEVELS: number;
export const PASS_CORRECT: number;
export const PROGRESS_VERSION: number;
export const STORAGE_KEY: string;
export function tierForLevel(level: number): number;
export function rankForLevel(level: number, ranks: Rank[]): Rank;
export function computePoints(correct: boolean, elapsedSeconds: number): number;
export function emptyProgress(): Progress;
export function normalizeProgress(raw: unknown): Progress;
export function canStartLevel(progress: Progress, level: number): boolean;
export function levelsMissingPerfect(progress: Progress, rank: Rank): number[];
export function finishLevel(progress: Progress, ranks: Rank[], level: number, input: { correct: number; times: number[]; points: number }): FinishOutcome;
