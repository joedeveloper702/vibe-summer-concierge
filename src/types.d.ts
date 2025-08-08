// Global type definitions for Cloudflare Workers
/// <reference types="@cloudflare/workers-types" />

// Re-export D1 and KV types to ensure they're available
declare global {
  interface D1Database {
    prepare(sql: string): D1PreparedStatement;
    dump(): Promise<ArrayBuffer>;
    batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
    exec(sql: string): Promise<D1ExecResult>;
  }

  interface KVNamespace {
    get(key: string, options?: KVNamespaceGetOptions<undefined>): Promise<string | null>;
    get(key: string, type: "text"): Promise<string | null>;
    get(key: string, type: "json"): Promise<any>;
    get(key: string, type: "arrayBuffer"): Promise<ArrayBuffer | null>;
    get(key: string, type: "stream"): Promise<ReadableStream | null>;
    get(key: string, options: KVNamespaceGetOptions<"text">): Promise<string | null>;
    get(key: string, options: KVNamespaceGetOptions<"json">): Promise<any>;
    get(key: string, options: KVNamespaceGetOptions<"arrayBuffer">): Promise<ArrayBuffer | null>;
    get(key: string, options: KVNamespaceGetOptions<"stream">): Promise<ReadableStream | null>;
    
    put(key: string, value: string | ArrayBuffer | ArrayBufferView | ReadableStream, options?: KVNamespacePutOptions): Promise<void>;
    
    delete(key: string): Promise<void>;
    
    list<Metadata = unknown>(options?: KVNamespaceListOptions): Promise<KVNamespaceListResult<Metadata>>;
  }
}

export {};
