<h2 align="center">Zygisk NoHello</h2>
<p align="center">
  A Zygisk module to hide root.
  </br>
  </br>
  <a href="https://github.com/MhmRdd/NoHello/actions/workflows/build.yml">
    <img src="https://github.com/MhmRdd/Il2Dump/actions/workflows/build.yml/badge.svg?branch=master" alt="Android CI status">
  </a>
  <a href="https://creativecommons.org/licenses/by-nc-sa/4.0/">
    <img src="https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg" alt="License: CC BY-NC-SA 4.0">
  </a>
  </br>
  <a href="https://github.com/MhmRdd/NoHello/issues">Report Bug</a>
    ·
  <a href="https://github.com/MhmRdd/NoHello/issues">Request Feature</a>
    ·
  <a href="https://github.com/MhmRdd/NoHello/releases">Latest Release</a>
</p>

> [!NOTE]
> This module currently focuses to hide root from apps and **NOT** zygisk.
> Updates will gradually implements changes and fixes.

## About The Project

Using the **release** build is recommended over the debug build. Only use debug builds if you are going to make a bug report.

## Usage

### KernelSU & APatch users:
1. Install ZygiskNext.
1. Make sure the unmount setting is enabled for the target app in the KernelSU/APatch Manager.
1. Disable `Enforce DenyList` in ZygiskNext settings if there is one.

### Magisk users:
1. Update your Magisk to 28.0 or newer for better hiding capabilities. (optional)
1. Turn on Zygisk in Magisk settings.
1. Turn off `Enforce DenyList` in Magisk settings.
1. Add the target app to the deny list unless you're using a Magisk fork with a white list instead.


## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project.
2. Create your Feature Branch (`git checkout -b feature/FeatureName`)
3. Commit your Changes (`git commit -m 'Add some FeatureName'`)
4. Push to the Branch (`git push origin feature/FeatureName`)
5. Open a Pull Request.