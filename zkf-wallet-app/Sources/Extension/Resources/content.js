(function installZirOSProviderBridge() {
  const scope = "ziros-midnight-wallet";
  const providerRequestScope = "ziros-provider-request";
  const providerResponseScope = "ziros-provider-response";

  window.addEventListener("message", async (event) => {
    if (event.source !== window || !event.data || event.data.scope !== providerRequestScope) {
      return;
    }

    const { id, method, params } = event.data;
    try {
      const result = await browser.runtime.sendMessage({
        scope,
        method,
        params,
      });
      window.postMessage({ scope: providerResponseScope, id, result }, "*");
    } catch (error) {
      window.postMessage(
        {
          scope: providerResponseScope,
          id,
          error: error instanceof Error ? error.message : String(error),
        },
        "*",
      );
    }
  });

  const script = document.createElement("script");
  script.textContent = `
    (() => {
      if (window.midnight?.ziros) {
        return;
      }

      const requestScope = ${JSON.stringify(providerRequestScope)};
      const responseScope = ${JSON.stringify(providerResponseScope)};
      const origin = window.location.origin;

      const call = (method, params = {}) => {
        const id = crypto.randomUUID();
        return new Promise((resolve, reject) => {
          const onMessage = (event) => {
            if (event.source !== window || !event.data || event.data.scope !== responseScope || event.data.id !== id) {
              return;
            }
            window.removeEventListener("message", onMessage);
            if (event.data.error) {
              reject(new Error(event.data.error));
              return;
            }
            resolve(event.data.result);
          };
          window.addEventListener("message", onMessage);
          window.postMessage(
            {
              scope: requestScope,
              id,
              method,
              params: { ...params, origin },
            },
            "*",
          );
        });
      };

      const provider = {
        rdns: "com.ziros.wallet",
        name: "ZirOS Wallet",
        icon: "",
        apiVersion: "4.0.1",
        async connect(networkId) {
          await call("connect", { networkId });
          return {
            getConfiguration: () => call("getConfiguration"),
            getConnectionStatus: () => call("getConnectionStatus"),
            getProvingProvider: () => call("getProvingProvider"),
            getBalances: () => call("getBalances"),
            getAddresses: () => call("getAddresses"),
            getActivity: () => call("getActivity").then((value) => value.items ?? value),
            makeTransfer: (desiredOutputs, options) =>
              call("makeTransfer", { desiredOutputs, options }),
            makeIntent: (desiredInputs, desiredOutputs, options) =>
              call("makeIntent", { desiredInputs, desiredOutputs, options }),
            hintUsage: () => Promise.resolve(),
          };
        },
      };

      window.midnight = window.midnight || {};
      window.midnight.ziros = provider;
    })();
  `;

  (document.documentElement || document.head || document.body).appendChild(script);
  script.remove();
})();
