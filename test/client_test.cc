#include "net/tools/test/client_test.h"

#include <utility>
#include<iostream>
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/chromium/quic_chromium_alarm_factory.h"
#include "net/quic/chromium/quic_chromium_connection_helper.h"
#include "net/quic/chromium/quic_chromium_packet_reader.h"
#include "net/quic/chromium/quic_chromium_packet_writer.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_ptr_util.h"
#include "net/socket/udp_client_socket.h"
#include "net/spdy/chromium/spdy_http_utils.h"
#include "net/spdy/core/spdy_header_block.h"

using std::string;

namespace net {

QuicClientTest::QuicClientTest(
    QuicSocketAddress server_address,
    const QuicServerId& server_id,
    const QuicVersionVector& supported_versions,
    std::unique_ptr<ProofVerifier> proof_verifier)
    : QuicClient(
          server_id,
          supported_versions,
          QuicConfig(),
          CreateQuicConnectionHelper(),
          CreateQuicAlarmFactory(),
          QuicWrapUnique(
              new QuicClientMessageLoop(&clock_, this)),
          std::move(proof_verifier)),
      initialized_(false),
      weak_factory_(this) {
  set_server_address(server_address);
}

QuicClientTest::~QuicClientTest() {
  if (connected()) {
    session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Shutting down",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
}
QuicClientTest::QuicDataToResend::QuicDataToResend(
    QuicStringPiece body,
    bool fin,
    QuicClientTest* client)
    : body_(body), fin_(fin),client_(client) {}

QuicClientTest::QuicDataToResend::~QuicDataToResend() {}

void QuicClientTest::QuicDataToResend::Resend() {
//  client_->SendData( body_, fin_);
}

QuicClientSession* QuicClientTest::client_session() {
  return static_cast<QuicClientSession*>(QuicClientTest::session());
}

void QuicClientTest::InitializeSession() {
  client_session()->Initialize();
  client_session()->CryptoConnect();
}

QuicChromiumConnectionHelper* QuicClientTest::CreateQuicConnectionHelper() {
  return new QuicChromiumConnectionHelper(&clock_, QuicRandom::GetInstance());
}

QuicChromiumAlarmFactory* QuicClientTest::CreateQuicAlarmFactory() {
  return new QuicChromiumAlarmFactory(base::ThreadTaskRunnerHandle::Get().get(),
                                      &clock_);
}

int QuicClientTest::GetNumSentClientHellosFromSession() {
  return client_session()->GetNumSentClientHellos();
}

int QuicClientTest::GetNumReceivedServerConfigUpdatesFromSession() {
  return client_session()->GetNumReceivedServerConfigUpdates();
}
void QuicClientTest::ResendSavedData() {
  // Calling Resend will re-enqueue the data, so swap out
  //  data_to_resend_on_connect_ before iterating.
  std::vector<std::unique_ptr<QuicDataToResend>> old_data;
  old_data.swap(data_to_resend_on_connect_);
  for (const auto& data : old_data) {
    data->Resend();
  }
}
void QuicClientTest::ClearDataToResend() {
  data_to_resend_on_connect_.clear();
}
void QuicClientTest::SendData(QuicStringPiece body,
                               bool fin) {

  QuicClientStream* stream = CreateClientStream();
  if (stream == nullptr) {
    QUIC_BUG << "stream creation failed!";
    return;
  }
  std::cout<<"send data"<<std::endl;
  while(1)
{
  string s;
  std::cin>>s;
  std::cout<<s;
  stream->SendData(s, fin);
  if (stream->HasBufferedData()) {
        WaitForEvents();
  }
 // stream->SendData( body, fin);
  // Record this in case we need to resend.
  MaybeAddDataToResend(s, fin);
}
}
void QuicClientTest::SendDataAndWait(QuicStringPiece body,
                               bool fin) {
  SendData(body, fin);
}



void QuicClientTest::MaybeAddDataToResend(
                                              QuicStringPiece body,
                                              bool fin) {
  if (!FLAGS_quic_reloadable_flag_enable_quic_stateless_reject_support) {
    return;
  }

  if (client_session()->IsCryptoHandshakeConfirmed()) {
    // The handshake is confirmed.  No need to continue saving requests to
    // resend.
    data_to_resend_on_connect_.clear();
    return;
  }
  std::unique_ptr<QuicDataToResend> data_to_resend(
      new QuicDataToResend(body, fin, this));
  MaybeAddQuicDataToResend(std::move(data_to_resend));
}
void QuicClientTest::MaybeAddQuicDataToResend(
    std::unique_ptr<QuicDataToResend> data_to_resend) {
  data_to_resend_on_connect_.push_back(std::move(data_to_resend));
}

std::unique_ptr<QuicSession> QuicClientTest::CreateQuicClientSession(
    QuicConnection* connection) {
  std::cout<<"CreateQuicClientSession"<<std::endl;
  return QuicMakeUnique<QuicClientSession>(*config(), connection,
                                               server_id(), crypto_config());
}
QuicClientStream* QuicClientTest::CreateClientStream() {
  if (!connected()) {
    return nullptr;
  }
  std::cout<<"CreateClientStream"<<std::endl;
  auto* stream = static_cast<QuicClientStream*>(
      FLAGS_quic_reloadable_flag_quic_refactor_stream_creation
          ? client_session()->MaybeCreateOutgoingDynamicStream(3)
          : client_session()->CreateOutgoingDynamicStream(3));
 /* if (stream) {
    stream->set_visitor(this);
  }*/
  return stream;
}
}  // namespace net

