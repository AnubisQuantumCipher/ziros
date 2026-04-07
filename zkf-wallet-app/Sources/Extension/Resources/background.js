const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const nativeMethod = async (method, params = {}) => {
  const response = await browser.runtime.sendNativeMessage("com.ziros.wallet.extension", {
    method,
    params,
  });
  if (response && response.error) {
    throw new Error(response.error);
  }
  return response;
};

const waitForApprovedResult = async (requestId) => {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const status = await nativeMethod("getRequestStatus", { requestId });
    if (status.state === "approved") {
      return status.result ?? {};
    }
    if (status.state === "rejected" || status.state === "failed") {
      throw new Error(status.error || `Bridge request ${requestId} failed`);
    }
    await sleep(1000);
  }
  throw new Error("auth_required: timed out waiting for native wallet approval.");
};

const invokeWallet = async (method, params = {}) => {
  const response = await nativeMethod(method, params);
  if (response && response.pendingRequestId) {
    return waitForApprovedResult(response.pendingRequestId);
  }
  return response;
};

browser.runtime.onMessage.addListener((message) => {
  if (!message || message.scope !== "ziros-midnight-wallet") {
    return undefined;
  }
  return invokeWallet(message.method, message.params);
});
