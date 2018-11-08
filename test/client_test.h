#ifndef NET_TOOLS_QUIC_QUIC_SIMPLE_CLIENT_H_
#define NET_TOOLS_QUIC_QUIC_SIMPLE_CLIENT_H_

#include <stddef.h>

#include <memory>
#include <string>

#include "base/command_line.h"
#include "base/macros.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log.h"
#include "net/quic/chromium/quic_chromium_packet_reader.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_stream.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/tools/test/quic_client_loop.h"
#include "net/tools/test/client_base.h"
#include "net/tools/test/client_session.h"
#include "net/tools/test/client_stream.h"
namespace net {

class QuicChromiumAlarmFactory;
class QuicChromiumConnectionHelper;

namespace test {
class QuicClientPeer;
}  // namespace test

class QuicClientTest : public QuicClient {
 public:
  // Create a quic client, which will have events managed by the message loop.
  QuicClientTest(QuicSocketAddress server_address,
                   const QuicServerId& server_id,
                   const QuicVersionVector& supported_versions,
                   std::unique_ptr<ProofVerifier> proof_verifier);

  ~QuicClientTest() override;
class QuicDataToResend {
   public:
    // |headers| may be null, since it's possible to send data without headers.
    QuicDataToResend(QuicStringPiece body,
                     bool fin,
		    QuicClientTest* client);

    virtual ~QuicDataToResend();

    // Must be overridden by specific classes with the actual method for
    // re-sending data.
     void Resend();

   protected:
    QuicStringPiece body_;
    bool fin_;
    QuicClientTest* client_;
   private:
    DISALLOW_COPY_AND_ASSIGN(QuicDataToResend);
  };
  std::unique_ptr<QuicSession> CreateQuicClientSession(
      QuicConnection* connection) override;
  void ClearDataToResend() override;
  void MaybeAddDataToResend(
                            QuicStringPiece body,
                            bool fin);
  void ResendSavedData() override;
  int GetNumSentClientHellosFromSession() override;
  int GetNumReceivedServerConfigUpdatesFromSession() override;
  QuicClientSession* client_session();
  void SendData(
                   QuicStringPiece body,
                   bool fin);
  void SendDataAndWait(
                   QuicStringPiece body,
                   bool fin);

  void MaybeAddQuicDataToResend(
      std::unique_ptr<QuicDataToResend> data_to_resend);
  QuicClientStream* CreateClientStream();
  void InitializeSession() override;
 private:
  friend class net::test::QuicClientPeer;
  std::vector<std::unique_ptr<QuicDataToResend>> data_to_resend_on_connect_;
  QuicChromiumAlarmFactory* CreateQuicAlarmFactory();
  QuicChromiumConnectionHelper* CreateQuicConnectionHelper();

  //  Used by |helper_| to time alarms.
  QuicChromiumClock clock_;

  // Tracks if the client is initialized to connect.
  bool initialized_;

  base::WeakPtrFactory<QuicClientTest> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicClientTest);
};
} 
#endif
