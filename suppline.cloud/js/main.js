/**
 * suppline Homepage - Main JavaScript
 * Handles navigation, interactivity, and responsive behavior
 */

document.addEventListener('DOMContentLoaded', function() {
    initializeNavigation();
    initializeSmoothScroll();
    initializeLazyLoading();
    initializeLightbox();
});

/**
 * Initialize mobile navigation hamburger menu
 */
function initializeNavigation() {
    const hamburger = document.getElementById('hamburger');
    const navMenu = document.getElementById('navMenu');

    if (!hamburger || !navMenu) return;

    /**
     * Close the navigation menu
     */
    function closeMenu() {
        hamburger.classList.remove('active');
        navMenu.classList.remove('active');
        hamburger.setAttribute('aria-expanded', 'false');
    }

    /**
     * Toggle the navigation menu
     */
    function toggleMenu() {
        hamburger.classList.toggle('active');
        navMenu.classList.toggle('active');
        const isExpanded = hamburger.getAttribute('aria-expanded') === 'true';
        hamburger.setAttribute('aria-expanded', !isExpanded);
    }

    // Toggle menu on hamburger click
    hamburger.addEventListener('click', function(e) {
        e.stopPropagation();
        toggleMenu();
    });

    // Handle touch events for better mobile experience
    hamburger.addEventListener('touchstart', function(e) {
        e.preventDefault();
        toggleMenu();
    }, { passive: false });

    // Close menu when a link is clicked
    const navLinks = navMenu.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            // Only close if it's an internal link (starts with #)
            if (this.getAttribute('href').startsWith('#')) {
                closeMenu();
            }
        });

        // Handle touch events on nav links
        link.addEventListener('touchend', function(e) {
            if (this.getAttribute('href').startsWith('#')) {
                closeMenu();
            }
        });
    });

    // Close menu when clicking outside
    document.addEventListener('click', function(event) {
        const isClickInsideNav = navMenu.contains(event.target);
        const isClickOnHamburger = hamburger.contains(event.target);

        if (!isClickInsideNav && !isClickOnHamburger && navMenu.classList.contains('active')) {
            closeMenu();
        }
    });

    // Close menu on escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && navMenu.classList.contains('active')) {
            closeMenu();
        }
    });

    // Handle window resize to close menu on larger screens
    window.addEventListener('resize', function() {
        if (window.innerWidth > 768 && navMenu.classList.contains('active')) {
            closeMenu();
        }
    });
}

/**
 * Initialize smooth scrolling for anchor links
 */
function initializeSmoothScroll() {
    const links = document.querySelectorAll('a[href^="#"]');

    links.forEach(link => {
        link.addEventListener('click', function(e) {
            const href = this.getAttribute('href');

            // Skip if href is just "#"
            if (href === '#') return;

            const target = document.querySelector(href);
            if (!target) return;

            e.preventDefault();

            // Calculate offset for sticky header
            const header = document.querySelector('.header');
            const headerHeight = header ? header.offsetHeight : 0;
            const targetPosition = target.offsetTop - headerHeight;

            // Use smooth scroll if supported, otherwise use instant scroll
            if ('scrollBehavior' in document.documentElement.style) {
                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            } else {
                // Fallback for browsers that don't support smooth scroll
                window.scrollTo(0, targetPosition);
            }
        });

        // Handle touch events for better mobile experience
        link.addEventListener('touchend', function(e) {
            const href = this.getAttribute('href');
            if (href === '#') return;

            const target = document.querySelector(href);
            if (!target) return;

            const header = document.querySelector('.header');
            const headerHeight = header ? header.offsetHeight : 0;
            const targetPosition = target.offsetTop - headerHeight;

            window.scrollTo({
                top: targetPosition,
                behavior: 'smooth'
            });
        });
    });
}

/**
 * Initialize lazy loading for images
 */
function initializeLazyLoading() {
    // Check if Intersection Observer is supported
    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    const src = img.dataset.src;
                    
                    if (src) {
                        img.src = src;
                        img.classList.add('loaded');
                        
                        // Remove data-src after loading to prevent re-loading
                        img.removeAttribute('data-src');
                    }
                    
                    observer.unobserve(img);
                }
            });
        }, {
            rootMargin: '50px'
        });

        // Observe all images with data-src attribute
        const lazyImages = document.querySelectorAll('img[data-src]');
        lazyImages.forEach(img => imageObserver.observe(img));
    } else {
        // Fallback for browsers without Intersection Observer support
        const lazyImages = document.querySelectorAll('img[data-src]');
        lazyImages.forEach(img => {
            img.src = img.dataset.src;
            img.classList.add('loaded');
        });
    }
}

/**
 * Utility function to check if element is in viewport
 */
function isInViewport(element) {
    const rect = element.getBoundingClientRect();
    return (
        rect.top >= 0 &&
        rect.left >= 0 &&
        rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
}

/**
 * Add scroll event listener for animations (optional enhancement)
 */
window.addEventListener('scroll', function() {
    // This can be used for scroll-triggered animations in the future
    // For now, it's a placeholder for potential enhancements
});

/**
 * Initialize lightbox modal for gallery images
 */
function initializeLightbox() {
    const lightbox = document.getElementById('lightbox');
    const lightboxImage = document.getElementById('lightbox-image');
    const lightboxCaption = document.getElementById('lightbox-caption');
    const lightboxCounter = document.getElementById('lightbox-counter');
    const lightboxClose = document.querySelector('.lightbox-close');
    const lightboxPrev = document.querySelector('.lightbox-prev');
    const lightboxNext = document.querySelector('.lightbox-next');
    const galleryImages = document.querySelectorAll('.gallery-image');

    if (!lightbox || galleryImages.length === 0) return;

    let currentIndex = 0;
    const images = Array.from(galleryImages).map(img => ({
        src: img.dataset.src || img.src,
        alt: img.alt,
        caption: img.closest('figure').querySelector('figcaption').textContent
    }));

    /**
     * Open lightbox with specific image
     */
    function openLightbox(index) {
        currentIndex = index;
        updateLightboxImage();
        lightbox.classList.add('active');
        lightbox.setAttribute('aria-hidden', 'false');
        document.body.style.overflow = 'hidden';
    }

    /**
     * Close lightbox
     */
    function closeLightbox() {
        lightbox.classList.remove('active');
        lightbox.setAttribute('aria-hidden', 'true');
        document.body.style.overflow = '';
    }

    /**
     * Update lightbox image and caption
     */
    function updateLightboxImage() {
        const image = images[currentIndex];
        lightboxImage.src = image.src;
        lightboxImage.alt = image.alt;
        lightboxCaption.textContent = image.caption;
        lightboxCounter.textContent = `${currentIndex + 1} / ${images.length}`;
    }

    /**
     * Show next image
     */
    function showNext() {
        currentIndex = (currentIndex + 1) % images.length;
        updateLightboxImage();
    }

    /**
     * Show previous image
     */
    function showPrev() {
        currentIndex = (currentIndex - 1 + images.length) % images.length;
        updateLightboxImage();
    }

    // Add click handlers to gallery images
    galleryImages.forEach((img, index) => {
        img.addEventListener('click', () => openLightbox(index));
        img.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                openLightbox(index);
            }
        });
        // Touch support for mobile
        img.addEventListener('touchend', (e) => {
            e.preventDefault();
            openLightbox(index);
        });
    });

    // Lightbox controls
    lightboxClose.addEventListener('click', closeLightbox);
    lightboxPrev.addEventListener('click', showPrev);
    lightboxNext.addEventListener('click', showNext);

    // Touch support for lightbox controls
    lightboxClose.addEventListener('touchend', (e) => {
        e.preventDefault();
        closeLightbox();
    });
    lightboxPrev.addEventListener('touchend', (e) => {
        e.preventDefault();
        showPrev();
    });
    lightboxNext.addEventListener('touchend', (e) => {
        e.preventDefault();
        showNext();
    });

    // Swipe gesture support for mobile
    let touchStartX = 0;
    let touchEndX = 0;

    lightbox.addEventListener('touchstart', (e) => {
        if (!lightbox.classList.contains('active')) return;
        touchStartX = e.changedTouches[0].screenX;
    }, false);

    lightbox.addEventListener('touchend', (e) => {
        if (!lightbox.classList.contains('active')) return;
        touchEndX = e.changedTouches[0].screenX;
        handleSwipe();
    }, false);

    function handleSwipe() {
        const swipeThreshold = 50;
        const diff = touchStartX - touchEndX;

        if (Math.abs(diff) > swipeThreshold) {
            if (diff > 0) {
                // Swiped left, show next image
                showNext();
            } else {
                // Swiped right, show previous image
                showPrev();
            }
        }
    }

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
        if (!lightbox.classList.contains('active')) return;

        switch(e.key) {
            case 'Escape':
                closeLightbox();
                break;
            case 'ArrowLeft':
                showPrev();
                break;
            case 'ArrowRight':
                showNext();
                break;
        }
    });

    // Close lightbox when clicking outside image
    lightbox.addEventListener('click', (e) => {
        if (e.target === lightbox) {
            closeLightbox();
        }
    });
}
