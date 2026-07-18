import type { ReactNode } from "react";
import { act, renderHook } from "@testing-library/react";

import {
  QueryControllerProvider,
  useQueryController,
} from "@/providers/QueryControllerProvider";

jest.mock("@/hooks/useTierAtLeast", () => ({
  useTierAtLeast: () => false,
}));

interface WrapperProps {
  children: ReactNode;
}

function Wrapper({ children }: WrapperProps) {
  return <QueryControllerProvider>{children}</QueryControllerProvider>;
}

describe("PMORG CE query controller", () => {
  it("keeps the default controller in chat mode", async () => {
    const { result } = renderHook(() => useQueryController(), {
      wrapper: Wrapper,
    });
    const onChat = jest.fn();

    act(() => result.current.setAppMode("search"));
    await act(async () => {
      await result.current.submit("status update", onChat);
    });

    expect(result.current.state).toEqual({ phase: "idle", appMode: "chat" });
    expect(result.current.searchResults).toEqual([]);
    expect(onChat).toHaveBeenCalledWith("status update");
  });
});
