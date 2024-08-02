# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class Grimoire < Formula
  desc ""
  homepage "https://github.com/DataDog/grimoire"
  version "0.0.1"
  license "Apache-2.0"

  on_macos do
    on_intel do
      url "https://github.com/DataDog/grimoire/releases/download/v0.0.1/grimoire_Darwin_x86_64.tar.gz"
      sha256 "a0a92ab60593a88503cc840a5207f69542772d40603c4c9092d13e78326fd253"

      def install
        bin.install "grimoire"
      end
    end
    on_arm do
      url "https://github.com/DataDog/grimoire/releases/download/v0.0.1/grimoire_Darwin_arm64.tar.gz"
      sha256 "619633491406e5772110ff8931c47aba01b26add3172c1f4c121d52dd96c464c"

      def install
        bin.install "grimoire"
      end
    end
  end

  on_linux do
    on_intel do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/DataDog/grimoire/releases/download/v0.0.1/grimoire_Linux_x86_64.tar.gz"
        sha256 "e98fc99f43260e9cffc2dc639fb9634b70c5ffe5becdb12c6ed864e6a1ad2816"

        def install
          bin.install "grimoire"
        end
      end
    end
    on_arm do
      if Hardware::CPU.is_64_bit?
        url "https://github.com/DataDog/grimoire/releases/download/v0.0.1/grimoire_Linux_arm64.tar.gz"
        sha256 "da872e00a990213954a14f8b648ee97437f1a7b6fa3bc8cb8a65600a3c92d673"

        def install
          bin.install "grimoire"
        end
      end
    end
  end
end