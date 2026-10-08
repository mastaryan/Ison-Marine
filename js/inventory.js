/* Ison Marine — inventory renderer.
 * All boat listings render from /data/boats.json.
 * Add a boat: edit data/boats.json (or use tools/add-boat.html), push, deploy. No HTML edits needed.
 *
 * Containers:
 *   <div data-inventory data-status="available">                        -> current-inventory cards
 *   <div data-inventory data-status="available" data-consignment="true" data-card="consignment">
 *                                                                      -> consignment cards
 *   <div data-inventory data-status="available" data-brand="cigarette"> -> in-stock strip on brand pages
 *   <div data-sold-gallery>                                             -> sold photo gallery (GLightbox)
 */
(function () {
  'use strict';

  var DATA_URL = '/data/boats.json';
  var CONTACT_URL = '/about-us/contact-us.html';

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function money(n) {
    if (n == null || n === '') return '';
    return '$' + Number(n).toLocaleString('en-US');
  }

  function detailLink(boat) {
    if (boat.detailPage) return { href: boat.detailPage, label: boat.buttonLabel || 'View Details' };
    return { href: CONTACT_URL, label: 'Contact Us' };
  }

  /* Exact markup of the current-inventory gallery cards */
  function galleryCard(boat) {
    var link = detailLink(boat);
    return (
      '<div class="gallery-item">' +
        '<img alt="' + esc(boat.name) + '" src="' + esc(boat.image) + '" loading="lazy" />' +
        '<h3>' + esc(boat.name) + '</h3>' +
        '<p>Price: ' + esc(money(boat.price)) + '</p>' +
        '<p>' + esc(boat.blurb || '') + '</p>' +
        '<a class="custom-btn" href="' + esc(link.href) + '">' + esc(link.label) + '</a>' +
      '</div>'
    );
  }

  /* Exact markup of the consignment cards */
  function consignmentCard(boat) {
    var link = detailLink(boat);
    return (
      '<div class="col">' +
        '<div class="text-center consignment-card">' +
          '<img src="' + esc(boat.image) + '" class="img-fluid shadow mb-4" alt="' + esc(boat.name) + '" loading="lazy">' +
          '<h3>' + esc(boat.name) + '</h3>' +
          '<p class="fw-bold text-primary fs-4 mb-2">' + esc(money(boat.price)) + '</p>' +
          '<p class="mb-4">' + esc(boat.blurb || '') + '</p>' +
          '<a href="' + esc(link.href) + '" class="btn btn-primary">' + esc(link.label) + '</a>' +
        '</div>' +
      '</div>'
    );
  }

  /* Sold photo gallery — same markup/classes the footer GLightbox init expects */
  function soldItem(photo) {
    return (
      '<a href="' + esc(photo.src) + '" class="glightbox" data-gallery="sold" data-glightbox="title: ' + esc(photo.title) + '">' +
        '<img src="' + esc(photo.src) + '" alt="' + esc(photo.title) + '" class="img-fluid rounded shadow gallery-thumb" style="max-height: 300px; object-fit: cover;" loading="lazy">' +
      '</a>'
    );
  }

  function emptyMsg(text) {
    return '<p class="text-muted text-center w-100">' + esc(text) + '</p>';
  }

  function renderInventory() {
    var containers = document.querySelectorAll('[data-inventory]');
    var soldContainers = document.querySelectorAll('[data-sold-gallery]');
    if (!containers.length && !soldContainers.length) return;

    fetch(DATA_URL, { cache: 'no-store' })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (data) {
        var boats = data.boats || [];

        containers.forEach(function (el) {
          var status = el.getAttribute('data-status') || 'available';
          var consignmentOnly = el.getAttribute('data-consignment') === 'true';
          var brand = el.getAttribute('data-brand');
          var cardStyle = el.getAttribute('data-card') || 'gallery';

          var list = boats.filter(function (b) {
            if (b.status !== status) return false;
            if (consignmentOnly && !b.consignment) return false;
            if (brand && b.brand !== brand) return false;
            return true;
          });

          if (!list.length) {
            el.innerHTML = emptyMsg(brand ? 'No ' + brand + ' boats in stock right now — check back soon.' : 'New listings coming soon.');
            return;
          }
          el.innerHTML = list.map(cardStyle === 'consignment' ? consignmentCard : galleryCard).join('');
        });

        soldContainers.forEach(function (el) {
          var photos = data.soldGallery || [];
          if (!photos.length) {
            el.innerHTML = emptyMsg('Sold gallery coming soon.');
            return;
          }
          el.innerHTML = photos.map(soldItem).join('');
          initSoldLightbox();
        });
      })
      .catch(function () {
        containers.forEach(function (el) {
          el.innerHTML = emptyMsg('Inventory is temporarily unavailable. Please call us for current listings.');
        });
        soldContainers.forEach(function (el) {
          el.innerHTML = emptyMsg('Gallery is temporarily unavailable.');
        });
      });
  }

  /* GLightbox for the dynamically-rendered sold gallery.
   * The footer inits GLightbox (possibly before our fetch resolves); we just
   * reload its instance so it picks up the rendered anchors. */
  function initSoldLightbox() {
    var opts = {
      selector: '.glightbox',
      touchNavigation: true,
      loop: true,
      keyboardNavigation: true,
      closeOnOutsideClick: true,
      width: '90vw',
      height: '90vh'
    };
    if (window._isonLightbox && typeof window._isonLightbox.reload === 'function') {
      window._isonLightbox.reload();
      return;
    }
    if (window.GLightbox) {
      window._isonLightbox = window.GLightbox(opts);
      return;
    }
    var tries = 0;
    var t = setInterval(function () {
      tries++;
      if ((window._isonLightbox && typeof window._isonLightbox.reload === 'function') || window.GLightbox || tries > 50) {
        clearInterval(t);
        if (window._isonLightbox && typeof window._isonLightbox.reload === 'function') window._isonLightbox.reload();
        else if (window.GLightbox) window._isonLightbox = window.GLightbox(opts);
      }
    }, 100);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderInventory);
  } else {
    renderInventory();
  }
})();
