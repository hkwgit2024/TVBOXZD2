// src/types/iptv.ts

export interface IPTVChannel {
  id: string; // e.g., stream_id from Xtream or a generated ID from M3U
  name: string;
  logoUrl: string | null;
  category: string; // Or categoryId
  streamUrl: string;
  epgData?: {
    title: string;
    startTime: string; // ISO string or timestamp
    endTime: string; // ISO string or timestamp
    description?: string;
  };
  dataAiHint?: string; // For placeholder images
  // Fields from Xtream available_channels
  stream_type?: 'live' | 'movie' | 'series'; // Raw type from Xtream
  epg_channel_id?: string | null;
  added?: string; // Timestamp string
  tv_archive?: 0 | 1;
  direct_source?: string;
  tv_archive_duration?: number | string; // Can be string like "0" or number
  container_extension?: string; // e.g. "ts"
}

export interface IPTVMovie {
  id: string; // e.g., stream_id from Xtream or a generated ID from M3U
  name: string;
  coverImageUrl: string | null;
  category: string; // Or categoryId
  streamUrl: string;
  rating?: number | string;
  year?: string;
  plot?: string;
  cast?: string;
  director?: string;
  genre?: string;
  duration?: string; // e.g., "1h 30m" or minutes as string/number
  dataAiHint?: string; // For placeholder images
  // Fields from Xtream movie_data
  stream_type?: 'movie';
  rating_5based?: number | string;
  added?: string; // Timestamp string
  container_extension?: string; // e.g. "mp4", "mkv"
  custom_sid?: string;
  direct_source?: string;
}

export interface IPTVEpisode {
  id: string; // e.g., episode_id from Xtream
  title: string;
  seasonNumber: number;
  episodeNumber: number;
  streamUrl: string;
  coverImageUrl?: string | null;
  plot?: string;
  duration?: string; // e.g., "45m" or minutes
  releaseDate?: string;
  rating?: number | string;
  dataAiHint?: string; // For placeholder images
  // Fields from Xtream series episode info
  container_extension?: string;
  added?: string; // Timestamp string
}

export interface IPTVSeries {
  id: string; // e.g., series_id from Xtream
  name: string;
  coverImageUrl: string | null;
  category: string; // Or categoryId
  plot?: string;
  cast?: string;
  director?: string;
  genre?: string;
  releaseDate?: string; // Typically YYYY-MM-DD
  rating?: number | string;
  seasonsCount?: number;
  episodesCount?: number; // Total episodes, if available
  dataAiHint?: string; // For placeholder images
  // Fields from Xtream series_data
  last_modified?: string; // Timestamp string
  rating_5based?: number | string;
  episode_run_time?: string;
  youtube_trailer?: string;
  backdrop_path?: string[];
  cover?: string; // Alternative for coverImageUrl
  series_id?: string | number; // Raw series_id from API
  seasons?: Array<{season_number: number; name: string; episode_count: number; air_date: string | null}>; // From get_series_info
}


export interface IPTVCategory {
  id: string; // category_id
  name: string;
  type: 'live' | 'movie' | 'series'; // To distinguish category types
  parentId?: string | null;
}

// Mirroring the structure from the user's specification for Xtream API user_info
export interface XtreamUserInfo {
  username: string;
  password?: string; // Usually not returned for security
  message?: string;
  auth: 0 | 1; // 1 for authenticated, 0 for not
  status: string; // "Active", "Expired", "Banned", "Disabled"
  exp_date: string | null; // "1609459199" (timestamp as string) or null
  is_trial: "0" | "1";
  active_cons: string; // "0"
  created_at: string; // "1577836800" (timestamp as string)
  max_connections: string; // "1"
  allowed_output_formats?: string[]; // ["m3u8", "ts"]
}

export interface XtreamServerInfo {
  url: string; // hostname e.g. "bavarian.ottct.pro"
  port: string;
  https_port?: string;
  server_protocol?: "http" | "https";
  rtmp_port?: string;
  timezone?: string; // "Europe/Paris"
  timestamp_now?: string; // "1606750216"
  time_now?: string; // "2020-11-30 15:30:16"
}

export interface IPTVAccountInfo {
  username: string;
  status: string; // e.g. "Active"
  expiryDate: string | null; // ISO string format after conversion
  isTrial: boolean;
  activeConnections: number;
  maxConnections: number;
  createdAt?: string | null; // ISO string format after conversion
  // Raw API responses for more detailed debugging or future use
  rawUserInfo?: XtreamUserInfo;
  rawServerInfo?: XtreamServerInfo;
}

export interface IPTVData {
  liveChannels: IPTVChannel[];
  movies: IPTVMovie[];
  series: IPTVSeries[];
  categories: {
    live: IPTVCategory[];
    movie: IPTVCategory[];
    series: IPTVCategory[];
  };
  accountInfo: IPTVAccountInfo | null; // This will store the processed account info
  sourceType: 'm3u' | 'xtream';
  dataSourceUrl: string; // The original URL (host:port for Xtream, full URL for M3U)
  // Raw data from Xtream for detailed views or future processing
  rawAvailableChannels?: any[];
  rawMovieData?: any[];
  rawSeriesData?: any[];
}

// Result from the server action `loadIPTVSourceAction`
export interface LoadIPTVSourceResult {
  success: boolean;
  data?: IPTVData;
  error?: string;
  validationErrors?: Record<string, string>;
}

// For DNS Status check
export interface DnsStatusResult {
  status: 'Online' | 'Maintenance' | 'Offline' | 'Checking...' | 'Error';
  statusCode?: number | null;
  error?: string | null;
}
