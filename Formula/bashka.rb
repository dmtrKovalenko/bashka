# Tap from this repo: brew tap dmtrKovalenko/bashka https://github.com/dmtrKovalenko/bashka
# The version and sha256 lines are pinned by CI on every release (make pin-installer).
class Bashka < Formula
  desc "Safety guard for `curl … | bash`: analyzes the script before it runs"
  homepage "https://github.com/dmtrKovalenko/bashka"
  version "0.10.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/dmtrKovalenko/bashka/releases/download/v0.10.0/bashka-aarch64-apple-darwin"
      sha256 "6d126a6acd7b6403af7c1efcdc3ea77731f4d60d1c00496e809021df4ba3edfc"
    end
    on_intel do
      url "https://github.com/dmtrKovalenko/bashka/releases/download/v0.10.0/bashka-x86_64-apple-darwin"
      sha256 "8cc3036869bb8bc9a3e5ec0441ea00178c7b03620a7fe018f9fbaf8a05ec20a2"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/dmtrKovalenko/bashka/releases/download/v0.10.0/bashka-aarch64-unknown-linux-musl"
      sha256 "74e0d5cbd3822e7a522cde71c59d360ac25ebbf26b665f086b23f423aebb88c0"
    end
    on_intel do
      url "https://github.com/dmtrKovalenko/bashka/releases/download/v0.10.0/bashka-x86_64-unknown-linux-musl"
      sha256 "5f9742759a6d8581de2c34d9424af162c87e42de0357e0a46e7ae36f1bfcf019"
    end
  end

  def install
    bin.install Dir["bashka*"].first => "bashka"
    chmod 0755, bin/"bashka"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bashka --version")
  end
end
