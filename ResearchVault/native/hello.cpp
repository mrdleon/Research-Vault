// Build with MSVC x64 and Windows 11 SDK. Called only on a Python worker thread.
#include <windows.h>
#include <userconsentverifierinterop.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.UI.h>
extern "C" __declspec(dllexport) int __cdecl verify_hello(HWND hwnd) noexcept {
    try {
        winrt::init_apartment(winrt::apartment_type::multi_threaded);
        int code = -1;
        try {
            using namespace winrt::Windows::Security::Credentials::UI;
            auto factory = winrt::get_activation_factory<UserConsentVerifier, IUserConsentVerifierInterop>();
            auto operation = winrt::capture<winrt::Windows::Foundation::IAsyncOperation<UserConsentVerificationResult>>(
                factory, &IUserConsentVerifierInterop::RequestVerificationForWindowAsync,
                hwnd, reinterpret_cast<HSTRING>(winrt::get_abi(winrt::hstring(L"ResearchVault: verifikasi akses vault penelitian"))));
            code = static_cast<int>(operation.get());
        } catch (...) { code = -1; }
        winrt::uninit_apartment();
        return code;
    } catch (...) { return -1; }
}
