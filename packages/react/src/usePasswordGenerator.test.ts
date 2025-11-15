import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { usePasswordGenerator } from './usePasswordGenerator';

describe('usePasswordGenerator', () => {
  it('should initialize with empty password', () => {
    const { result } = renderHook(() => usePasswordGenerator());
    
    expect(result.current.password).toBe('');
    expect(result.current.loading).toBe(false);
    expect(result.current.result).toBeNull();
  });

  it('should generate password with default options', async () => {
    const { result } = renderHook(() => usePasswordGenerator());
    
    await act(async () => {
      await result.current.generate();
    });

    expect(result.current.password).toBeTruthy();
    expect(result.current.password.length).toBeGreaterThanOrEqual(16);
    expect(result.current.result).toBeTruthy();
    expect(result.current.result?.entropy).toBeGreaterThan(0);
  });

  it('should generate password with custom options', async () => {
    const { result } = renderHook(() => 
      usePasswordGenerator({ length: 20 })
    );
    
    await act(async () => {
      await result.current.generate();
    });

    expect(result.current.password.length).toBe(20);
  });

  it('should override options on generate call', async () => {
    const { result } = renderHook(() => 
      usePasswordGenerator({ length: 16 })
    );
    
    await act(async () => {
      await result.current.generate({ length: 32 });
    });

    expect(result.current.password.length).toBe(32);
  });

  it('should handle loading state', async () => {
    const { result } = renderHook(() => usePasswordGenerator());
    
    expect(result.current.loading).toBe(false);

    const generatePromise = act(async () => {
      await result.current.generate();
    });

    await generatePromise;

    expect(result.current.loading).toBe(false);
  });

  it('should clear password', async () => {
    const { result } = renderHook(() => usePasswordGenerator());
    
    await act(async () => {
      await result.current.generate();
    });

    expect(result.current.password).toBeTruthy();

    act(() => {
      result.current.clear();
    });

    expect(result.current.password).toBe('');
    expect(result.current.result).toBeNull();
  });

  it('should maintain options between renders', async () => {
    const { result, rerender } = renderHook(() => 
      usePasswordGenerator({ 
        length: 16,
        includeSymbols: false 
      })
    );
    
    await act(async () => {
      await result.current.generate();
    });

    const firstPassword = result.current.password;
    
    rerender();

    await act(async () => {
      await result.current.generate();
    });

    // Both passwords should be 16 characters
    expect(firstPassword.length).toBe(16);
    expect(result.current.password.length).toBe(16);
  });
});
