class RcloneEncryptTest < Formula
  desc "Minimal CLI for rclone-compatible encryption/decryption"
  homepage "https://github.com/yetanotherchris/rclone-encrypt-test-chatgpt"
  version "0.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-chatgpt/releases/download/v0.0.0/rclone-encrypt-test-darwin-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-chatgpt/releases/download/v0.0.0/rclone-encrypt-test-darwin-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-chatgpt/releases/download/v0.0.0/rclone-encrypt-test-linux-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-chatgpt/releases/download/v0.0.0/rclone-encrypt-test-linux-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "rclone-encrypt-test-darwin-arm64" => "rclone-encrypt-test" if OS.mac? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-test-darwin-amd64" => "rclone-encrypt-test" if OS.mac? && !Hardware::CPU.arm?
    bin.install "rclone-encrypt-test-linux-arm64" => "rclone-encrypt-test" if OS.linux? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-test-linux-amd64" => "rclone-encrypt-test" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "rclone-encrypt-test #{version}", shell_output("#{bin}/rclone-encrypt-test --version")
  end
end
