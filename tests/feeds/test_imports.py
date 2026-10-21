def test_packages_importable():
    import php2mon.feeds
    import php2mon.web

    assert php2mon.feeds.__name__ == "php2mon.feeds"
    assert php2mon.web.__name__ == "php2mon.web"
